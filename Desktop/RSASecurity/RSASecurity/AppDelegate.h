//
//  AppDelegate.h
//  RSASecurity
//
//  Created by 杨勇 on 17/3/16.
//  Copyright © 2017年 qqqq. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

