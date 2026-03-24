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
detection_name: SSL Group "Queen"
version: 32
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Verizon Wireless' => 'Telecom and Internet provider.',
          'TwitchTV' => 'Justin.tv gaming specific livestreaming platform.',
          'PNC Bank' => 'Banking and Financial services.',
          'Vine' => 'Mobile App for sharing photos and videos clips.',
          'Yahoo! Calendar' => 'Yahoo! online calendar app.',
          'Allstate' => 'Insurance company.',
          'Zendesk' => 'Customer support web application.',
          'United Airlines' => 'Online Flight reservation from United Airlines.',
          'TextNow' => 'Instant text and voice services.',
          'Yahoo!' => 'Yahoo! and it\'s online services.',
          'Yahoo! Mail' => 'Yahoo!\'s mail client.',
          'Yammer' => 'Enterprise social networking site.',
          'Eventbrite' => 'Event organization and invite site.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'Nvidia' => 'Video chipset manufacturer.',
          'MLive' => 'News local to the American state of Michigan.',
          'Geico' => 'Insurance company.',
          'GoBank' => 'A bank that focuses on mobile banking.',
          'Box' => 'File storage and transfer site.',
          'Adobe Software' => 'Adobe software and updates.',
          'StudentUniverse' => 'Travel booking and price comparison site for students.',
          'The Huffington Post' => 'Online news website.',
          'American Airlines' => 'Airline services and travel planner.',
          'Bitbucket' => 'Source code hosting site.',
          'Nuance' => 'Airline services and travel planner.',
          'J.P. Morgan' => 'Financial services arm of J.P. Morgan Chase & Co.',
          'FedEx' => 'Courier delivery services.',
          'Jetsetz' => 'Travel booking and price comparison site.',
          'Red Hat' => 'Open-source software products.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_reo",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Box
    { 0, 1326, 'boxcloud.com' },
    { 0, 1326, 'box.com' },
    { 0, 1326, 'box.net' },
    { 0, 1326, 'box.org' },
    { 0, 1326, 'boxcdn.net' },
    { 0, 1326, 'boxrelay.com' },
    -- Eventbrite
    { 0, 2139, 'eventbrite.com' },
    -- Fidelity
    { 0, 636, 'fidelity.com' },
    -- J.P. Morgan
    { 0, 2140, 'jpmorgan.com' },
    { 0, 2140, 'jpmm.com' },
    -- GoBank
    { 0, 2141, 'gobank.com' },
    -- Verizon Wireless
    { 0, 1388, 'verizonwireless.com' },
    { 0, 1388, 'myvzw.com' },
    { 0, 1388, 'vzw.com' },
    -- Allstate
    { 0, 2154, 'allstate.com' },
    { 0, 2154, 'allstate.reviewability.com' },
    -- geico
    { 0, 2155, 'geico.com' },
    -- TwitchTV
    { 0, 1051, 'twitch.tv' },
    { 0, 1051, 'ext-twitch.tv' },
    { 0, 1051, 'jtvnw.net' },
    { 0, 1051, 'ttvnw.net' },
    { 0, 1051, 'twitchcdn.net' },
    -- { 0, 1051, 'twitchsvc.net' },
    -- PNC Bank
    { 0, 2172, 'pnc.com' },
    { 0, 2172, 'pncmc.com' },
    { 0, 2172, 'pncactivepay.com' },
    -- Red Hat
    { 0, 2173, 'redhat.com' },
    -- StudentUniverse
    { 0, 2161, 'studentuniverse.com' },
    -- StudentUniverse
    { 0, 2160, 'jetsetz.com' },
    -- United Airlines
    { 0, 2174, 'united.com' },
    -- Nvidia
    { 0, 2150, 'nvidia.com' },
    -- Zendesk
    { 0, 2128, 'zendesk.com' },
    { 0, 2128, 'zdassets.com' },
    -- Adobe Software
    { 0, 541, 'macromedia.com' },
    -- TextNow 
    { 1, 2176, 'textnow.me' },
    { 0, 2176, 'textnow.com' },
    -- FedEx 
    { 0, 2177, 'fedex.com' },
    { 0, 2177, 'fedex.tt.omtrdc.net' },
    -- American Airlines
    { 0, 2178, 'aa.com' },
    { 0, 2178, 'aavacations.com' },
    -- Huffingtonpost 
    { 0, 1370, 'huffingtonpost.com' },
    { 0, 1370, 'huffpost.com' },
    -- Nuance
    { 0, 2179, 'nuance.com' },
    { 0, 2179, 'nuan.netmng.com' },
    -- MLive
    { 0, 2182, 'mlive.com' },
    -- Vine
    { 0, 1700, 'vine.co' },
    -- Bitbucket
    { 0, 2185, 'bitbucket.org' },
    -- Yahoo! Mail
    { 0, 946, 'mail.yahoo.com' },
    -- Yahoo!
    { 0, 524, 'yahooapis.com' },
    -- Yahoo! Calednar
    { 0, 2196, 'calendar.yahoo.com' },
    -- Yammer
    { 0, 2198, 'yammer.com' },
    { 0, 2198, 'assets-yammer.com' },
    { 0, 2198, 'yammerusercontent.com' },

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

