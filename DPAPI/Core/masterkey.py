#!/usr/bin/env python

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## This document is the property of Cassidian SAS, it may not be copied or ##
## circulated without prior licence                                        ##
##                                                                         ##
##  Author: Jean-Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import string
import crypto
import hashlib
import os, re
from collections import defaultdict
from eater import Eater, DataStruct
from DPAPI.Core import credhist


class MasterKey(DataStruct):
    def __init__(self, raw=None):
        self.decrypted = False
        self.key = None
        self.hmacSalt= None
        self.hmac = None
        self.hmacComputed = None
        DataStruct.__init__(self, raw)
        
    def parse(self, data):
        self.version = data.eat("L")
        self.iv = data.eat("16s")
        self.rounds = data.eat("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.ciphertext = data.remain()

    def decryptWithHash(self, userSID, pwdhash):
        self.decryptWithKey(crypto.derivePwdHash(pwdhash, userSID, self.hashAlgo))

    def decryptWithPassword(self, userSID, pwd):
        self.decryptWithKey(crypto.derivePassword(pwd, userSID, self.hashAlgo))

    def decryptWithKey(self, pwdhash):
        if self.decrypted:
            return
        ## Compute encryption key
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.ciphertext, 
                                      pwdhash, self.iv, self.rounds)
        self.key = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmac = cleartxt[16:16+self.hashAlgo.digestLength]
        self.hmacComputed = crypto.DPAPIHmac(self.hashAlgo, pwdhash,
                                             self.hmacSalt, self.key)
        self.decrypted = self.hmac == self.hmacComputed

    def __repr__(self):
        s = ["Masterkey block"]
        s.append("        cipher algo  = %s" % repr(self.cipherAlgo))
        s.append("        hash algo    = %s" % repr(self.hashAlgo))
        s.append("        rounds       = %i" % self.rounds)
        s.append("        IV           = %s" % self.iv.encode("hex"))
        if self.key is not None:
            s.append("        key          = %s" % self.key.encode("hex"))
            s.append("        hmacSalt     = %s" % self.hmacSalt.encode("hex"))
            s.append("        hmac         = %s" % self.hmac.encode("hex"))
            s.append("        hmacComputed = %s" % self.hmacComputed.encode("hex"))
        else:
            s.append("        ciphertext   = %s" % self.ciphertext.encode("hex"))
        return "\n".join(s)


class CredHist(DataStruct):
    def parse(self, data):
        self.magic = data.eat("L")
        self.guid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")
    def __repr__(self):
        s = ["CredHist block"]
        s.append("        magic\t= %(magic)d" % self.__dict__)
        s.append("        guid\t= %s" % self.guid)
        return "\n".join(s)

class DomainKey(DataStruct):
    def parse(self, data):
        self.version = data.eat("L")
        self.secretLen = data.eat("L")
        self.accesscheckLen = data.eat("L")
        self.guidKey = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B") #data.eat("16s")
        self.encryptedSecret = data.eat("%us" % self.secretLen)
        self.accessCheck = data.eat("%us" % self.accesscheckLen)
    def __repr__(self):
        s = ["DomainKey block"]
        s.append("        version\t= %x" % self.version)
        s.append("        guid\t= %s" % self.guidKey)
        s.append("        secret\t= %s" % self.encryptedSecret.encode("hex"))
        s.append("        accessCheck\t= %s" % self.accessCheck.encode("hex"))
        return "\n".join(s)

class MasterKeyFile(DataStruct):
    def __init__(self, raw=None):
        self.masterkey = None
        self.backupkey = None
        self.credhist = None
        self.domainkey = None
        self.decrypted = False
        DataStruct.__init__(self, raw)
        
    def parse(self, data):
        self.version = data.eat("L")
        data.eat("2L")
        self.guid = data.eat("72s").decode("UTF-16LE").encode("utf-8")
        data.eat("2L")
        self.flags = data.eat("L")
        self.masterkeyLen = data.eat("Q")
        self.backupkeyLen = data.eat("Q")
        self.credhistLen = data.eat("Q")
        self.domainkeyLen = data.eat("Q")
        
        if self.masterkeyLen > 0:
            self.masterkey = MasterKey()
            self.masterkey.parse(data.eat_sub(self.masterkeyLen))
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey()
            self.backupkey.parse(data.eat_sub(self.backupkeyLen))
        if self.credhistLen > 0:
            self.credhist = CredHist()
            self.credhist.parse(data.eat_sub(self.credhistLen))
        if self.domainkeyLen > 0:
            self.domainkey = DomainKey()
            self.domainkey.parse(data.eat_sub(self.domainkeyLen))

    def decryptWithHash(self, userSID, h):
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithHash(userSID, h)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithHash(userSID, h)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def decryptWithPassword(self, userSID, pwd):
        self.decryptWithHash(userSID, hashlib.sha1(pwd.encode('UTF-16LE')).digest())

    def decryptWithKey(self, pwdhash):
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithKey(pwdhash)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithKey(pwdhash)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted
    
    def get_key(self):
        if self.masterkey.decrypted:
            return self.masterkey.key
        elif self.backupkey.decrypted:
            return self.backupkey.key
        return self.masterkey.key
        

    def __repr__(self):
        s = ["\n#### MasterKeyFile %s ####" % self.guid]
        s.append("""        version   = %(version)#d
        Flags     = %(flags)#x
        MasterKey = %(masterkeyLen)d
        BackupKey = %(backupkeyLen)d
        CredHist  = %(credhistLen)d
        DomainKey = %(domainkeyLen)d""" % self.__dict__)
        if self.masterkey:
            s.append("    + Master Key: %s" % repr(self.masterkey))
        if self.backupkey:
            s.append("    + Backup Key: %s" % repr(self.backupkey))
        if self.credhist:
            s.append("    + %s" % repr(self.credhist))
        if self.domainkey:
            s.append("    + %s" % repr(self.domainkey))
        return "\n".join(s)


class MasterKeyPool:
    def __init__(self):
        self.keys = defaultdict(lambda: [])
        self.creds = {}
        self.system = None

    def addMasterKey(self, mkey):
        mkf = MasterKeyFile(mkey)
        self.keys[mkf.guid].append(mkf)

    def getMasterKeys(self, guid):
        return self.keys.get(guid,[])

    def addSystemCredential(self, blob):
        self.system = credhist.CredSystem(blob)

    def addCredhist(self, sid, cred):
        self.creds[sid] = cred

    def addCredhistFile(self, sid, credfile):
        f = open(credfile)
        self.addCredhist(sid, credhist.CredHistFile(f.read()))
        f.close()

    def loadDirectory(self, directory):
        for k in os.listdir(directory):
            if re.match("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", k, re.IGNORECASE):
                try:
                    f = open(os.path.join(directory, k))
                    self.addMasterKey(f.read())
                    f.close()
                except:
                    pass

    def try_credential(self, userSID, password):
        n = 0
        for mk in self.keys.values():
            if not mk.decrypted:
                mk.decryptWithPassword(userSID, password)
                if mk.decrypted:
                    n += 1
        return n

    def __repr__(self):
        s  = [ "MasterKeyPool:" ]
        s.append("Keys:")
        s.append(repr(self.keys.items()))
        s.append(repr(self.system))
        s.append("CredHist entries:")
        for i in self.creds.keys():
            s.append("\tSID: %s" % i)
            s.append(repr(self.creds[i]))
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
