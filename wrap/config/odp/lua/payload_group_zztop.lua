--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: Payload Group "ZZTop"
version: 1
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'QQ Music' => 'Tencent streaming music.',
          'Tencent Video' => 'Tencent streaming video.',
          'Tencent Cloud' => 'Tencent cloud services.',
          'QQ Pay' => 'Tencent online payment service.',
          'QQ Games' => 'Multi-Player online game by QQ.',
          'QQ Mail' => 'Tencent email service.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_zztop",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- QQ Mail
    { 0, 0, 0, 1913, 4, "mail.qq.com", "/", "http:", "", 3882},
    { 0, 0, 0, 1913, 4, "qqmail.com", "/", "http:", "", 3882},
    { 0, 0, 0, 1913, 4, "exmail.qq.com", "/", "http:", "", 3882},
    -- Tencent Cloud
    { 0, 0, 0, 1914, 9, "cloud.tencent.com", "/", "http:", "", 3880},
    { 0, 0, 0, 1914, 9, "qcloud.com", "/", "http:", "", 3880},
    { 0, 0, 0, 1914, 9, "weiyun.com", "/", "http:", "", 3880},
    { 0, 0, 0, 1914, 9, "qqweiyun.cn", "/", "http:", "", 3880},
    { 0, 0, 0, 1914, 9, "qq.com", "/weiyun", "http:", "", 3880},
    -- QQ Games
    { 0, 0, 0, 1917, 20, "game.gtimg.cn", "/", "http:", "", 3727},
    { 0, 0, 0, 1917, 20, "qqgame.qq.com", "/", "http:", "", 3727},
    { 0, 0, 0, 1917, 20, "game.qq.com", "/", "http:", "", 3727},
    { 0, 0, 0, 1917, 20, "tgb.qq.com", "/", "http:", "", 3727},
    { 0, 0, 0, 1917, 20, "tgp.qq.com", "/", "http:", "", 3727},
    { 0, 0, 0, 1917, 20, "dldir1.qq.com", "/box/QQmicrogamebox", "http:", "", 3727},
    -- QQ Music
    { 0, 0, 0, 1915, 2, "y.qq.com", "/", "http:", "", 3941},
    { 0, 0, 0, 1915, 2, "y.gtimg.cn", "/", "http:", "", 3941},
    -- Tencent Video
    { 0, 0, 0, 1916, 1, "v.qq.com", "/", "http:", "", 3942},
    { 0, 0, 0, 1916, 1, "video.qq.com", "/", "http:", "", 3942},
    { 0, 0, 0, 1916, 1, "vm.gtimg.cn", "/", "http:", "", 3942},
    -- QQ Pay
    { 0, 0, 0, 1918, 40, "pay.qq.com", "/", "http:", "", 3883},
    { 0, 0, 0, 1918, 40, "payqqp.com", "/", "http:", "", 3883},
    { 0, 0, 0, 1918, 40, "tenpay.com", "/", "http:", "", 3883},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

