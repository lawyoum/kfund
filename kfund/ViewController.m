//
//  ViewController.m
//  kfund
//
//  Created by Seo Hyun-gyu on 1/2/24.
//

#import "ViewController.h"
#import "post-exploit/jailbreak.h"

static UITextView *logTextView_ = nil;

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *logTextView;
@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;

@end

@implementation ViewController
- (IBAction)jailbreakButtonPressed:(UIButton *)sender {
    start_jailbreak();
}

- (void)viewDidLoad {
    [super viewDidLoad];
    logTextView_ = self.logTextView;
    // Do any additional setup after loading the view.
}

@end

void print_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    char str[512];
    vsnprintf(str, 512, format, args);
    
    NSString *logStr = [NSString stringWithCString:str encoding:NSUTF8StringEncoding];
    logStr = [NSString stringWithFormat:@"%@\n", logStr];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *currentText = logTextView_.text;
        NSString *newText = [currentText stringByAppendingString:logStr];
        [logTextView_ setText:newText];
        [logTextView_ scrollRangeToVisible:NSMakeRange(newText.length, 0)];
    });
}
