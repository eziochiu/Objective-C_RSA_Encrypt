//
//  RSAEncrypt.swift
//  Objective-C_RSA_Encrypt
//
//  Created by Ezio Chiu on 5/16/20.
//  Copyright © 2020 Ezio Chiu. All rights reserved.
//

import UIKit
import Security

open class RSAEncrypt: NSObject {
    
    
    static func base64_encode(data:Data!) -> String {
        return data.base64EncodedString(options: .lineLength64Characters);
    }
    
    static func base64_decode(string:String!) -> Data {
        let data = Data(base64Encoded: string, options: .ignoreUnknownCharacters)
        return data!
    }
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    class func stripPublicKeyHeader(key: Data?) -> Data? {
        guard let d_key = key else {
            return nil
        }
        guard let len = key?.count else {
            return nil
        }
        var c_key = [UInt8](repeating: 0, count: d_key.count / MemoryLayout<CUnsignedChar>.size)
        (d_key as NSData).getBytes(&c_key, length: d_key.count)
        var idx = 0
        if c_key[idx] != 0x30 {
            return nil
        }
        idx += 1
        
        if Int(c_key[idx]) > 0x80 {
            idx += Int(c_key[idx]) - 0x80 + 1
        } else {
            idx += 1
        }
        let seqiod = [UInt8](arrayLiteral: 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)
        
        for i in idx..<idx + 15 {
            if ( c_key[i] != seqiod[i-idx] ) {
                return nil
            }
        }
        idx += 15;
        
        if Int(c_key[idx]) != 0x03 {
            return nil
        }
        idx += 1
        
        if Int(c_key[idx]) > 0x80 {
            idx += Int(c_key[idx]) - 0x80 + 1
        } else {
            idx += 1
        }

        if c_key[idx] != 0x00 {
            return nil
        }
        idx += 1

        return Data(bytes: &c_key[idx], count: Int(len - idx))
    }
    
    class func stripPrivateKeyHeader(_ key: Data?) -> Data? {
        // Skip ASN.1 private key header
        guard let d_key = key else {
            return nil
        }
        guard let len = key?.count else {
            return nil
        }
        var c_key = [UInt8](repeating: 0, count: d_key.count / MemoryLayout<UInt8>.size)
        (d_key as NSData).getBytes(&c_key, length: d_key.count)
        var idx = 22
        if c_key[idx] != 0x04 {
            return d_key
        }
        idx += 1

        //calculate length of the key
        var c_len = UInt(c_key[idx])
        idx += 1
        let det = Int(c_len & 0x80)
        if det == 0 {
            c_len = c_len & 0x7f
        } else {
            var byteCount = Int(c_len & 0x7f)
            if byteCount + Int(idx) > Int(len) {
                //rsa length field longer than buffer
                return nil
            }
            var accum: UInt = 0
            var ptr = UInt8(c_key[idx])
            idx += Int(UInt(byteCount))
            while byteCount > 0 {
                accum = (accum << 8) + UInt(ptr)
                ptr += 1
                byteCount -= 1
            }
            c_len = accum
        }

        // Now make a new NSData from this buffer
        return d_key.subdata(in: idx..<idx + Int(c_len))
    }
    
    class func addPublicKey(key: String!) -> SecKey? {
        var nKey = key!
        let spos = NSString(string: nKey).range(of: "-----BEGIN PUBLIC KEY-----", options: .caseInsensitive)
        let epos = NSString(string: nKey).range(of: "-----END PUBLIC KEY-----", options: .caseInsensitive)
        if spos.location != NSNotFound && epos.location != NSNotFound {
            let s = spos.location + spos.length
            let e = epos.location
            let range = NSRange(location: s, length: e - s)
            nKey = NSString(string: nKey).substring(with: range)
        }
        
        nKey = nKey.replacingOccurrences(of: "\r", with: "")
        nKey = nKey.replacingOccurrences(of: "\n", with: "")
        nKey = nKey.replacingOccurrences(of: "\t", with: "")
        nKey = nKey.replacingOccurrences(of: " " , with: "")
        
        let data = base64_decode(string: nKey)
        guard let nData = RSAEncrypt.stripPublicKeyHeader(key: data) else { return nil }
        
        let tag = "RSAUtil_PubKey"
        let d_tag = tag.data(using: .utf8)
        
        var publicKey = [CFString: Any]();
        publicKey[kSecClass] = kSecClassKey
        publicKey[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        publicKey[kSecAttrApplicationTag] = d_tag
        publicKey[kSecValueData] = nData
        publicKey[kSecAttrKeyClass] = kSecAttrKeyClassPublic
        publicKey[kSecReturnPersistentRef] = true
        
        var status = SecItemAdd(publicKey as CFDictionary, nil)
        if (status != noErr) && (status != errSecDuplicateItem) {
            return nil
        }
        publicKey[kSecValueData] = nil
        publicKey[kSecReturnPersistentRef] = nil
        publicKey[kSecReturnRef] = true
        publicKey[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        
        var keyRef: AnyObject?
        status = SecItemCopyMatching(publicKey as CFDictionary, &keyRef)
        if status != noErr || keyRef == nil {
            return nil
        }
        return keyRef as! SecKey?
    }
    
    class func addPrivateKey(key: String!) -> SecKey? {
        let range = NSRange(location: 0, length: key.lengthOfBytes(using: .utf8))
        let regExp = try! NSRegularExpression(pattern: "(-----BEGIN.*?-----)|(-----END.*?-----)|\\s+", options: [])
        let base64 = regExp.stringByReplacingMatches(in: key, options: [], range: range, withTemplate: "")
        
        let data = base64_decode(string: base64)
        guard let nData = RSAEncrypt.stripPrivateKeyHeader(data) else { return nil }
        
        let tag = "RSAUtil_PrivKey"
        let d_tag = tag.data(using: .utf8)
        
        var publicKey = [CFString: Any]();
        publicKey[kSecClass] = kSecClassKey
        publicKey[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        publicKey[kSecAttrApplicationTag] = d_tag
        publicKey[kSecValueData] = nData
        publicKey[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
        publicKey[kSecReturnPersistentRef] = true
        
        var status = SecItemAdd(publicKey as CFDictionary, nil)
        if (status != noErr) && (status != errSecDuplicateItem) {
            return nil
        }
        publicKey[kSecValueData] = nil
        publicKey[kSecReturnPersistentRef] = nil
        publicKey[kSecReturnRef] = true
        publicKey[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        
        var keyRef: AnyObject?
        status = SecItemCopyMatching(publicKey as CFDictionary, &keyRef)
        if status != noErr || keyRef == nil {
            return nil
        }
        return keyRef as! SecKey?
    }
    
    class func encryptData(data: Data, keyRef:SecKey, isSign: Bool) -> Data? {
        let block_size = SecKeyGetBlockSize(keyRef)
        let data_size = data.count / MemoryLayout<UInt8>.size
        let src_block_size = block_size - 11

        var srclen = [UInt8](repeating: 0, count: data_size)
        (data as NSData).getBytes(&srclen, length: data_size)

        var encryptedData = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while (idx < srclen.count ) {
            var idxEnd = idx + src_block_size
            if ( idxEnd > srclen.count ) {
                idxEnd = srclen.count
            }
            var chunkData = [UInt8](repeating: 0, count: src_block_size)
            for i in idx..<idxEnd {
                chunkData[i-idx] = srclen[i]
            }

            var encryptedDataBuffer = [UInt8](repeating: 0, count: block_size)
            var encryptedDataLength = block_size

            let status = SecKeyEncrypt(keyRef, .PKCS1, chunkData, idxEnd-idx, &encryptedDataBuffer, &encryptedDataLength)
            if ( status != noErr ) {
                NSLog("Error while encrypting: %i", status)
                return nil
            }
            encryptedData += encryptedDataBuffer

            idx += src_block_size
        }

        return Data(bytes: UnsafePointer<UInt8>(encryptedData), count: encryptedData.count)
    }
    
    @objc class func encryptString(string: String, privKey: String) -> String {
        let data = RSAEncrypt.encryptData(data: string.data(using: .utf8)!, privKey: privKey)
        let ret = base64_encode(data: data)
        return ret
    }
    
    class func encryptData(data: Data?, privKey: String?) -> Data? {
        guard let nData = data, let nPrivKey = privKey else {
            return nil
        }
        guard let keyRef = RSAEncrypt .addPrivateKey(key: nPrivKey) else {
            return nil
        }
        return RSAEncrypt.encryptData(data: nData, keyRef: keyRef, isSign: true)
    }
    
    class func decryptData(data: Data, keyRef:SecKey) -> Data? {
        let block_size = SecKeyGetBlockSize(keyRef)
        let data_size = data.count / MemoryLayout<UInt8>.size

        var srclen = [UInt8](repeating: 0, count: data_size)
        (data as NSData).getBytes(&srclen, length: data_size)

        var decryptedData = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while (idx < srclen.count ) {
            var idxEnd = idx + block_size
            if ( idxEnd > srclen.count ) {
                idxEnd = srclen.count
            }
            var chunkData = [UInt8](repeating: 0, count: block_size)
            for i in idx..<idxEnd {
                chunkData[i-idx] = srclen[i]
            }

            var decryptedDataBuffer = [UInt8](repeating: 0, count: block_size)
            var decryptedDataLength = block_size

            let status = SecKeyDecrypt(keyRef, .PKCS1, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            if ( status != noErr ) {
                return nil
            }
            let finalData = removePadding(decryptedDataBuffer)
            decryptedData += finalData

            idx += block_size
        }

        return Data(bytes: UnsafePointer<UInt8>(decryptedData), count: decryptedData.count)
    }
    
    private static func removePadding(_ data: [UInt8]) -> [UInt8] {
        var idxFirstZero = -1
        var idxNextZero = data.count
        for i in 0..<data.count {
            if ( data[i] == 0 ) {
                if ( idxFirstZero < 0 ) {
                    idxFirstZero = i
                } else {
                    idxNextZero = i
                    break
                }
            }
        }
        if ( idxNextZero-idxFirstZero-1 == 0 ) {
            idxNextZero = idxFirstZero
            idxFirstZero = -1
        }
        var newData = [UInt8](repeating: 0, count: idxNextZero-idxFirstZero-1)
        for i in idxFirstZero+1..<idxNextZero {
            newData[i-idxFirstZero-1] = data[i]
        }
        return newData
    }
    
    @objc class func decryptString(string: String, privKey: String) -> String {
        var data = Data(base64Encoded: string, options: .ignoreUnknownCharacters)
        data = RSAEncrypt.decryptData(data: data!, privKey: privKey)
        return String(data: data!, encoding: .utf8)!
    }
    
    class func decryptData(data: Data?, privKey: String?) -> Data? {
        guard let nData = data, let nPrivKey = privKey else {
            return nil
        }
        guard let keyRef = RSAEncrypt.addPrivateKey(key: nPrivKey) else {
            return nil
        }
        return RSAEncrypt.decryptData(data: nData, keyRef: keyRef)
    }

    /* END: Encryption & Decryption with RSA private key */

    /* START: Encryption & Decryption with RSA public key */
    
    @objc class func encryptString(string: String, pubKey: String) -> String {
        let data = RSAEncrypt.encryptData(data: string.data(using: .utf8)!, pubKey: pubKey)
        return base64_encode(data: data)
    }
    
    class func encryptData(data: Data?, pubKey: String?) -> Data? {
        guard let nData = data, let nPubKey = pubKey else {
            return nil
        }
        guard let keyRef = RSAEncrypt.addPublicKey(key: nPubKey) else {
            return nil
        }
        return RSAEncrypt.encryptData(data: nData, keyRef: keyRef, isSign: false)
    }
    
    @objc class func decryptString(string: String, pubKey: String) -> String {
        var data = Data(base64Encoded: string, options: .ignoreUnknownCharacters)
        data = RSAEncrypt.decryptData(data: data, pubKey: pubKey)
        return String(data: data!, encoding: .utf8)!
    }
    
    class func decryptData(data: Data?, pubKey:String?) -> Data? {
        guard let nData = data, let nPubKey = pubKey else {
            return nil
        }
        guard let keyRef = RSAEncrypt.addPublicKey(key: nPubKey) else {
            return nil
        }
        return RSAEncrypt.decryptData(data: nData, keyRef: keyRef)
    }
}
