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
detection_name: Payload Group "354"
version: 2
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'PUBg' => 'A multiplayer shooter game to fight in the battleground.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_354",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- PUBg
    { 0, 0, 0, 2320, 20, "pubgserverping.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "pubg.disquse.ru", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "pubgbluehole.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "pubgm.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "cloud.vmp.onezapp.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "cloudctrl.gcloudsdk.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "idcconfig.gcloudsdk.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "igamecj.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "midasbuy.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "midas.gtimg.cn", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "napubgm.broker.amsoveasea.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "playbattlegrounds.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "proximabeta.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "pubg.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "pubgmobile.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "pubgmobile.proximabeta.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "vibeacon.onezapp.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "k.gjacky.com", "/", "http:", "", 4666},
    { 0, 0, 0, 2320, 20, "gpubgm.com", "/", "http:", "", 4666},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    gDetector:addHttpPattern(2, 5, 0, 542, 19, 0, 0, 'PUBG%20MOBILE', 4666, 1)

    return gDetector;
end

function DetectorClean()
end
