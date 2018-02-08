//
//  ideviceinstaller.h
//  XTool-Mac
//
//  Created by tpeng on 2018/2/7.
//  Copyright © 2018年 tpeng. All rights reserved.
//

#ifndef ideviceinstaller_h
#define ideviceinstaller_h

#include <stdio.h>

void install_app(void (* funcpntr)(void));
void run_func(void (* funcpntr)(void));

#endif /* ideviceinstaller_h */
