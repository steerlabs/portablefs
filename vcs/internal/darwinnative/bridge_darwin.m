//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

enum {
    PFSExactAppLaunchCompleted = 0,
    PFSExactAppLaunchRejected = 1,
    PFSExactAppLaunchCompletionTimedOut = 2,
    PFSExactAppLaunchWrongThread = 3,
};

@interface PFSExactAppLaunchCompletion : NSObject {
    NSCondition *_condition;
    BOOL _completed;
    BOOL _waiterPresent;
    NSString *_errorMessage;
}
- (void)completeWithApplication:(NSRunningApplication *)application
                          error:(NSError *)error;
- (BOOL)pollCompletedWithErrorOut:(char **)errorOut;
- (void)abandonWaiter;
@end

@implementation PFSExactAppLaunchCompletion
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _condition = [[NSCondition alloc] init];
        _waiterPresent = YES;
    }
    return self;
}

- (void)dealloc {
    [_errorMessage release];
    [_condition release];
    [super dealloc];
}

- (void)completeWithApplication:(NSRunningApplication *)application
                          error:(NSError *)error {
    [_condition lock];
    if (!_completed) {
        _completed = YES;
        if (_waiterPresent) {
            if (error != nil) {
                _errorMessage = [error.localizedDescription copy];
            } else if (application == nil) {
                _errorMessage = [@"host launch returned no running application" copy];
            }
        }
        [_condition broadcast];
    }
    [_condition unlock];
}

- (BOOL)pollCompletedWithErrorOut:(char **)errorOut {
    [_condition lock];
    if (!_completed) {
        [_condition unlock];
        return NO;
    }
    if (_errorMessage != nil && errorOut != NULL) {
        const char *message = _errorMessage.UTF8String;
        *errorOut = strdup(message != NULL ? message : "host launch failed");
    }
    _waiterPresent = NO;
    [_condition unlock];
    return YES;
}

- (void)abandonWaiter {
    [_condition lock];
    _waiterPresent = NO;
    [_condition unlock];
}
@end

char *portablefs_app_group_container_path(const char *identifier) {
    if (identifier == NULL) {
        return NULL;
    }
    @autoreleasepool {
        NSString *group = [NSString stringWithUTF8String:identifier];
        if (group == nil) {
            return NULL;
        }
        NSURL *container = [[NSFileManager defaultManager]
            containerURLForSecurityApplicationGroupIdentifier:group];
        if (container == nil || !container.isFileURL) {
            return NULL;
        }
        NSURL *canonical = container.URLByResolvingSymlinksInPath.standardizedURL;
        const char *path = canonical.fileSystemRepresentation;
        if (path == NULL || path[0] != '/') {
            return NULL;
        }
        return strdup(path);
    }
}

int portablefs_launch_exact_host(const char *path, char **errorOut) {
    if (errorOut != NULL) {
        *errorOut = NULL;
    }
    if (path == NULL) {
        if (errorOut != NULL) *errorOut = strdup("app path is missing");
        return PFSExactAppLaunchRejected;
    }
    // AppKit launch delivery itself depends on the process main RunLoop. A
    // background-thread call is a definite refusal before NSWorkspace, not an
    // ambiguous request that callers may reconcile as possibly launched.
    if (pthread_main_np() == 0) {
        return PFSExactAppLaunchWrongThread;
    }
    @autoreleasepool {
        NSString *appPath = [NSString stringWithUTF8String:path];
        if (appPath == nil) {
            if (errorOut != NULL) *errorOut = strdup("app path is not UTF-8");
            return PFSExactAppLaunchRejected;
        }
        NSURL *appURL = [NSURL fileURLWithPath:appPath isDirectory:YES];
        NSWorkspaceOpenConfiguration *configuration =
            [NSWorkspaceOpenConfiguration configuration];
        configuration.activates = NO;
        configuration.allowsRunningApplicationSubstitution = NO;

        PFSExactAppLaunchCompletion *completion =
            [[PFSExactAppLaunchCompletion alloc] init];
        // NSWorkspace owns the callback lifetime. Keep an independent retain
        // until it fires so a timeout cannot leave a block writing through
        // caller-owned storage after this function returns.
        [completion retain];
        [[NSWorkspace sharedWorkspace]
            openApplicationAtURL:appURL
            configuration:configuration
            completionHandler:^(NSRunningApplication *application, NSError *error) {
                [completion completeWithApplication:application error:error];
                [completion release];
            }];
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:10.0];
        BOOL delivered = NO;
        while (!(delivered = [completion pollCompletedWithErrorOut:errorOut]) &&
               [deadline timeIntervalSinceNow] > 0) {
            NSTimeInterval remaining = [deadline timeIntervalSinceNow];
            NSTimeInterval interval = remaining < 0.05 ? remaining : 0.05;
            if (interval <= 0) {
                break;
            }
            NSDate *slice = [NSDate dateWithTimeIntervalSinceNow:interval];
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                      beforeDate:slice];
        }
        if (!delivered) {
            delivered = [completion pollCompletedWithErrorOut:errorOut];
        }
        if (!delivered) {
            [completion abandonWaiter];
        }
        [completion release];
        if (!delivered) {
            return PFSExactAppLaunchCompletionTimedOut;
        }
        return errorOut != NULL && *errorOut != NULL
            ? PFSExactAppLaunchRejected
            : PFSExactAppLaunchCompleted;
    }
}
