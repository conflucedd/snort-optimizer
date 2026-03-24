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
detection_name: SSL Group "Nirvana"
version: 7
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Zoho Chat' => 'A web-enabled group chat application.',
          'Zoho Wiki' => 'Zoho collaborative web space.',
          'Apple Maps' => 'Apple maps and navigation.',
          'Zoho Mail' => 'Zoho webmail.',
          'Plex TV' => 'Allows users to stream their own media from one device to others over the Plex TV network.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_nirvana",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- Plex TV
    { 1, 4524, 'plex.tv' },
    { 1, 4524, 'plextv.disqus.com' },
    { 1, 4524, 'plex.direct' },

    -- Apple Maps
    { 1, 2381, 'mapsconnect.apple.com' },
    { 1, 2381, 'ls.apple.com' },
    { 1, 2381, 'maps.apple.com' },
    -- Zoho Mail
    { 0, 530, 'mail.zoho.com' },
    { 0, 530, 'mailwsfree.zoho.com' },
    { 0, 530, 'mailwsorg.zoho.com' },
    { 1, 530, 'zmail.zoho.com' },

    -- Zoho Chat
    { 1, 529, 'chat.zoho.com' },
    { 1, 529, 'cliq.zoho.com' },

    -- Zoho Wiki
    { 0, 532, 'wiki.zoho.com' },
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
