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
detection_name: SSL Group "354"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'PUBg' => 'A multiplayer shooter game to fight in the battleground.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_354",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- PUBg
    {1, 4666, 'pubgserverping.com', },
    {1, 4666, 'pubg.disquse.ru', },
    {1, 4666, 'pubgbluehole.com', },
    {1, 4666, 'pubgm.com', },
    {1, 4666, 'cloudctrl.gcloudsdk.com', },
    {1, 4666, 'cloud.vmp.onezapp.com', },
    {1, 4666, 'idcconfig.gcloudsdk.com', },
    {1, 4666, 'igamecj.com', },
    {1, 4666, 'midasbuy.com', },
    {1, 4666, 'midas.gtimg.cn', },
    {1, 4666, 'napubgm.broker.amsoveasea.com', },
    {1, 4666, 'playbattlegrounds.com', },
    {1, 4666, 'proximabeta.com', },
    {1, 4666, 'pubg.com', },
    {1, 4666, 'pubgmobile.com', },
    {1, 4666, 'pubgmobile.proximabeta.com', },
    {1, 4666, 'vibeacon.onezapp.com', },
    {1, 4666, 'k.gjacky.com', },
    {1, 4666, 'gpubgm.com', },
}

gSSLCnamePatternList = {
    -- PUBg
    {0, 4666, 'pubg.com', },
    {0, 4666, 'pubgmobile.com', },
    {1, 4666, 'pubgserverping.com', },
    {1, 4666, 'pubg.disquse.ru', },
    {1, 4666, 'pubgbluehole.com', },
    {1, 4666, 'pubgm.com', },
    {1, 4666, 'cloudctrl.gcloudsdk.com', },
    {1, 4666, 'cloud.vmp.onezapp.com', },
    {1, 4666, 'idcconfig.gcloudsdk.com', },
    {1, 4666, 'igamecj.com', },
    {1, 4666, 'midasbuy.com', },
    {1, 4666, 'midas.gtimg.cn', },
    {1, 4666, 'napubgm.broker.amsoveasea.com', },
    {1, 4666, 'playbattlegrounds.com', },
    {1, 4666, 'proximabeta.com', },
    {1, 4666, 'pubgmobile.proximabeta.com', },
    {1, 4666, 'vibeacon.onezapp.com', },
    {1, 4666, 'k.gjacky.com', },
    {1, 4666, 'gpubgm.com', },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
