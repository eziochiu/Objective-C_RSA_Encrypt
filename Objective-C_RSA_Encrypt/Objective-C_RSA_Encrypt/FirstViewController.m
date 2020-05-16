//
//  FirstViewController.m
//  Objective-C_RSA_Encrypt
//
//  Created by Ezio Chiu on 5/16/20.
//  Copyright © 2020 Ezio Chiu. All rights reserved.
//

#import "FirstViewController.h"
#import "RSAEncrypt.h"

@interface FirstViewController ()

@end

@implementation FirstViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *pubkey = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"public" ofType:@"pem"] encoding:NSUTF8StringEncoding error:nil];
    NSString *privkey = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"] encoding:NSUTF8StringEncoding error:nil];;
    NSString *encrypted = [RSAEncrypt encryptString:@"Hello World!" publicKey:pubkey];
    NSLog(@"encrypted: %@", encrypted);
    NSString *decrypted = [RSAEncrypt decryptString:encrypted privateKey:privkey];
    NSLog(@"decrypted: %@", decrypted);
}


@end
