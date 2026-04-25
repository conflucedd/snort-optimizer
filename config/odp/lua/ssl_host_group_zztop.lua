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
detection_name: SSL Group "ZZTop"
version: 3
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'QQ Music' => 'Tencent streaming music.',
          'QQ Mail' => 'Tencent email service.',
          'QQ Games' => 'Multi-Player online game by QQ.',
          'Tencent Cloud' => 'Tencent cloud services.',
          'QQ Pay' => 'Tencent online payment service.',
          'Tencent' => 'Chinese portal for Internet service.',
          'Tencent Video' => 'Tencent streaming video.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_zztop",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- QQ Mail
    { 0, 3882, 'mail.qq.com' },
    { 0, 3882, 'qmail.com' },
    { 0, 3882, 'pop.qq.com' },
    { 0, 3882, 'qqmail.com' },
    { 0, 3882, 'exmail.qq.com' },
    { 0, 3882, 'ex.qq.com' },
    -- Tencent Cloud
    { 0, 3880, 'cloud.tencent.com' },
    { 0, 3880, 'qcloud.com' },
    { 0, 3880, 'weiyun.com' },
    { 0, 3880, 'qqweiyun.cn' },
    -- QQ Games
    { 0, 3727, 'qqgame.qq.com' },
    { 0, 3727, 'game.qq.com' },
    { 0, 3727, 'game.gtimg.cn' },
    { 0, 3727, 'minigame.qq.com' },
    { 0, 3727, 'tgb.qq.com' },
    { 0, 3727, 'tgp.qq.com' },
    -- QQ Music
    { 0, 3941, 'y.qq.com' },
    { 0, 3941, 'y.gtimg.cn'},
    -- Tencent Video
    { 0, 3942, 'v.qq.com' },
    -- QQ pay
    { 0, 3883, 'pay.qq.com' },
    { 0, 3883, 'tenpay.com' },
    -- Tencent
    { 0, 2815, 'tencent.com' },

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
