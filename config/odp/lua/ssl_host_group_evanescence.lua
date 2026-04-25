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
detection_name: SSL Group "evanescence"
version: 7
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Apple Update' => 'Apple software updating tool.',
          'Sway' => 'Microsoft collaboration tool.',
          'Office 365 Planner' => 'Microsoft online calendar.',
          'Messenger' => 'Facebook\'s standalone messenger app.',
          'Office Mobile' => 'Microsoft productivty apps for use on Android devices.',
          'Microsoft Visual Studio' => 'Microsoft Integrated Developer Environment and toolchain designed to make it easier to develop software for Microsoft platforms.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_evanescence",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Microsoft Visual Studsio
    { 0, 3979, 'dc.services.visualstudio.com' },
    { 0, 3979, 'vortex.data.microsoft.com' },

    -- Sway
    { 0, 4069, 'sway.com' },
    { 0, 4069, 'eus-www.sway-cdn.com' },
    { 0, 4069, 'wus-www.sway-cdn.com' },
    { 0, 4069, 'eus-www.sway-extensions.com' },
    { 0, 4069, 'wus-www.sway-extensions.com' },
    { 0, 4069, 'c.microsoft.com' },
    { 0, 4069, 'c1.microsoft.com' },

    -- Planner
    { 0, 4070, 'tasks.office.com' },
    { 0, 4070, 'controls.office.com' },
    { 0, 4070, 'tasks.osi.office.net' },
    { 0, 4070, 'clientlog.portal.office.com' },
    
    -- Office for iPad
    -- { 0, 4071, 'directory.services.live.com' },
    -- { 0, 4071, 'nexus.officeapps.live.com' },
    -- { 0, 4071, 'dc2.client.hip.live.com' },
    -- { 0, 4071, 'c.live.com' },
    -- { 0, 4071, 'docs.live.net' },
    -- { 0, 4071, 'sqm.microsoft.com' },
    -- { 0, 4071, 'watson.telemetry.microsoft.com' },
    -- { 0, 4071, 'sas.office.microsoft.com' },
    -- { 0, 4071, 'p100-sandbox.itunes.apple.com' },
    -- { 0, 4071, 'cl2.apple.com' },
    -- { 0, 4071, 'view.atdmt.com' },
    -- { 0, 4071, 'c.bing.com' },
    -- { 0, 4071, 'foodanddrink.services.appex.bing.com' },
    -- { 0, 4071, 'weather.tile.appex.bing.com' },
    -- { 0, 4071, 'partnerservices.getmicrosoftkey.com' },
    -- { 0, 4071, 'en-US.appex-rf.msn.com' },

    -- Office Mobile
    { 0, 4072, 'roaming.officeapps.live.com' },
    { 0, 4072, 'd.docs.live.net' },
    { 0, 4072, 'odcsm.officeapps.live.com' },
    { 0, 4072, 'wer.microsoft.com' },
    { 0, 4072, 'msft.sts.microsoft.com' },
    { 0, 4072, 'microsoft-my.sharepoint.com' },
    { 0, 4072, 'ms.tific.com' },
    { 0, 4072, 'auth.gfx.ms' },
    { 0, 4072, 'officeimg.vo.msecnd.net' },
    { 0, 4072, 'appex.bing.com' },
    { 0, 4072, 'appex-rf.msn.com' },
    { 0, 4072, 'appexsin.stb.s-msn.com' },

    -- Apple Update
    { 0, 32, 'swscan.apple.com' },
    { 0, 32, 'swquery.apple.com' },
    { 0, 32, 'swdownload.apple.com' },
    { 0, 32, 'swdist.apple.com' },    
    { 0, 32, 'phobos.apple.com' },
    { 0, 32, 'skl.apple.com' },
    { 0, 32, 'swcdn.apple.com' },
    { 0, 32, 'updates-http.cdn-apple.com' },
    { 0, 32, 'iosapps.itunes.apple.com' },
    { 0, 32, 'updates.cdn-apple.com' },
    { 0, 32, 'mesu.apple.com' },

    -- Messenger
    { 0, 4073, 'messenger.com' },
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

