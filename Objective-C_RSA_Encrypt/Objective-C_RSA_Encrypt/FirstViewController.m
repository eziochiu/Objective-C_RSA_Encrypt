//
//  FirstViewController.m
//  Objective-C_RSA_Encrypt
//
//  Created by Ezio Chiu on 5/16/20.
//  Copyright © 2020 Ezio Chiu. All rights reserved.
//

#import "FirstViewController.h"
#import "RSAEncryptOC.h"
#import "Objective_C_RSA_Encrypt-Swift.h"

@interface FirstViewController ()

@end

@implementation FirstViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *pubkey = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"public" ofType:@"pem"] encoding:NSUTF8StringEncoding error:nil];
    NSString *privkey = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"] encoding:NSUTF8StringEncoding error:nil];
    
    //OC
    NSString *encryptedOC = [RSAEncryptOC encryptString:@"Hello World!" publicKey:pubkey];
    NSLog(@"encryptedOC: %@", encryptedOC);
    NSString *decryptedOC = [RSAEncryptOC decryptString:encryptedOC privateKey:privkey];
    NSLog(@"decryptedOC: %@", decryptedOC);
    
    //Swift
    NSString *encrypted = [RSAEncrypt encryptStringWithString:@"Hello World!" pubKey:pubkey];
    NSLog(@"encrypted: %@", encrypted);
    NSString *decrypted = [RSAEncrypt decryptStringWithString:encrypted privKey:privkey];
    NSLog(@"decrypted: %@", decrypted);
}


@end
