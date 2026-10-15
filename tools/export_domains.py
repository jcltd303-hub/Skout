#!/usr/bin/env python3
"""Durably deduplicate certificate names while retaining endpoint evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile


def normalize(value):
    if not isinstance(value,str):
        return None
    value=value.strip().lower().removesuffix('.')
    base=value[2:] if value.startswith('*.') else value
    if len(value)>253:
        return None
    try:
        ipaddress.ip_address(base)
        return None
    except ValueError:
        pass
    labels=base.split('.')
    if len(labels)<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in labels):
        return None
    return value


def open_database(path):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path)
    version=db.execute('PRAGMA user_version').fetchone()[0]
    if version not in (0,1):
        db.close()
        raise ValueError('unsupported scout database version')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL,
            host TEXT NOT NULL, fingerprint TEXT NOT NULL,
            observed_at TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS evidence (
            name TEXT NOT NULL, event_id TEXT NOT NULL, source TEXT NOT NULL,
            PRIMARY KEY(name,event_id,source),
            FOREIGN KEY(name) REFERENCES names(name),
            FOREIGN KEY(event_id) REFERENCES events(event_id)
        );
        PRAGMA user_version=1;
    ''')
    db.execute('PRAGMA foreign_keys=ON')
    db.commit()
    return db


def name_evidence(cert):
    def values(raw):
        return raw if isinstance(raw,list) else [raw] if isinstance(raw,str) else []
    pairs=set()
    # l9tcpid's original `domain` is its SAN array. The new collector also
    # retains raw `san`, since its canonical `domain` includes valid CNs.
    san=cert.get('san')
    for raw in values(san if 'san' in cert else cert.get('domain')):
        name=normalize(raw)
        if name is not None:
            pairs.add((name,'san'))
    for raw in (cert.get('cn'),cert.get('common_name')):
        name=normalize(raw)
        if name is not None:
            pairs.add((name,'cn'))
    known={name for name,_ in pairs}
    for raw in values(cert.get('domain')):
        name=normalize(raw)
        if name is not None and name not in known:
            pairs.add((name,'certificate_domain'))
    return pairs


def observation_time(value):
    if isinstance(value,str):
        try:
            date=datetime.fromisoformat(value.replace('Z','+00:00'))
            if date.tzinfo is not None:
                return date.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def ingest(db,stream,live_output=None):
    stats={'read':0,'imported':0,'duplicates':0,'invalid':0,'without_certificate':0}
    pending=0
    try:
        for line in stream:
            if not line.strip():
                continue
            stats['read']+=1
            try:
                event=json.loads(line)
                if not isinstance(event,dict):
                    raise ValueError('event must be an object')
                ssl=event.get('ssl')
                cert=ssl.get('certificate') if isinstance(ssl,dict) else None
                if not isinstance(cert,dict) or not any(cert.get(key) for key in ('fingerprint','domain','san','cn','common_name')):
                    stats['without_certificate']+=1
                    continue
                ip=str(ipaddress.ip_address(event.get('ip','')))
                raw_port=event.get('port')
                if isinstance(raw_port,bool) or not isinstance(raw_port,(str,int)):
                    raise ValueError('invalid port')
                port=int(raw_port)
                if not 1<=port<=65535:
                    raise ValueError('port out of range')
                raw=json.dumps(event,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
                host=event.get('host') or ''
                fingerprint=cert.get('fingerprint') or ''
                if not isinstance(host,str) or not isinstance(fingerprint,str):
                    raise ValueError('invalid endpoint or fingerprint')
            except (ValueError,TypeError):
                stats['invalid']+=1
                continue
            identity=hashlib.sha256(raw.encode('utf-8')).hexdigest()
            if not db.in_transaction:
                db.execute('BEGIN')
            db.execute('SAVEPOINT observation')
            new_names=[]
            try:
                cursor=db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)',
                                  (identity,ip,port,host,fingerprint,observation_time(event.get('time')),raw))
                if cursor.rowcount==0:
                    db.execute('RELEASE observation')
                    stats['duplicates']+=1
                    continue
                for name,source in sorted(name_evidence(cert)):
                    added=db.execute('INSERT OR IGNORE INTO names VALUES (?)',(name,))
                    if added.rowcount:
                        new_names.append(name)
                    db.execute('INSERT OR IGNORE INTO evidence VALUES (?,?,?)',(name,identity,source))
                db.execute('RELEASE observation')
            except BaseException:
                db.execute('ROLLBACK TO observation')
                db.execute('RELEASE observation')
                raise
            stats['imported']+=1
            pending+=1
            if live_output is not None or pending>=1000:
                db.commit()
                pending=0
            if live_output is not None:
                for name in new_names:
                    live_output.write(name+'\n')
                live_output.flush()
    finally:
        # Keep completed observations even when stdin is interrupted; replay is idempotent.
        db.commit()
    stats['unique_names']=db.execute('SELECT COUNT(*) FROM names').fetchone()[0]
    return stats


def atomic_write(path,write):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as output:
            write(output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def export(db,domains_path,evidence_path=None):
    db_path=Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve()
    targets=[Path(domains_path).resolve()]
    if evidence_path is not None:
        targets.append(Path(evidence_path).resolve())
    if db_path in targets or len(set(targets))!=len(targets):
        raise ValueError('database, domains and evidence output paths must be distinct')

    def names(output):
        for (name,) in db.execute('SELECT name FROM names ORDER BY name'):
            output.write(name+'\n')
    atomic_write(domains_path,names)

    if evidence_path is not None:
        def observations(output):
            for name,source,identity,ip,port,host,fingerprint,date,raw in db.execute('''
                SELECT p.name,p.source,e.event_id,e.ip,e.port,e.host,e.fingerprint,e.observed_at,e.raw_json
                FROM evidence p JOIN events e ON e.event_id=p.event_id
                ORDER BY p.name,e.ip,e.port,e.host,e.observed_at,p.source
            '''):
                cert=json.loads(raw)['ssl']['certificate']
                item={'domain':name,'source':source,'event_id':identity,'ip':ip,'port':port,'host':host,
                      'certificate_fingerprint':fingerprint,'observed_at':date,'certificate':cert}
                output.write(json.dumps(item,sort_keys=True,separators=(',',':'))+'\n')
        atomic_write(evidence_path,observations)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',default='scout.sqlite',type=Path)
    parser.add_argument('--domains',default='domains.txt',type=Path)
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--stream',action='store_true',help='Print newly discovered names immediately after committing their evidence')
    args=parser.parse_args(argv)
    paths=[args.database.resolve(),args.domains.resolve()]
    if args.evidence is not None:
        paths.append(args.evidence.resolve())
    if len(paths)!=len(set(paths)):
        parser.error('database, domains and evidence output paths must be distinct')
    db=open_database(args.database)
    try:
        stats=ingest(db,sys.stdin,live_output=sys.stdout if args.stream else None)
        export(db,args.domains,args.evidence)
        print(json.dumps(stats,sort_keys=True),file=sys.stderr)
        return 1 if stats['invalid'] else 0
    finally:
        db.close()


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,sqlite3.Error,ValueError) as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(1)
