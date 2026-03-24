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
detection_name: Payload Group "Perl Jam"
version: 1
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Zoho Assist' => 'A remote support and remote access software.',
          'Zoho Social' => 'A social media management tool.',
          'Nintendo' => 'Content delivery and web traffic from Nintendo, a Japanese company.',
          'Zoho Docs' => 'Online document management software that lets you manage and store all your files on the cloud.',
          'Zoho SalesIQ Chat' => 'Live chat software for website visitors and for customer support.',
          'Zoho Connect' => 'A team collaboration software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_perl_jam",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Nintendo
    { 0, 0, 0, 1904, 34, "nintendo.com", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.net", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendoofamerica.tt.omtrdc.net", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendoofamericainc.demdex.net", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.co.jp", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.co.kr", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.tw", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.co.nz", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.at", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.be", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendods.cz", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.dk", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.de", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.es", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.fi", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.fr", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.gr", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.hu", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.it", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.nl", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.no", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.pl", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.pt", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.ru", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.co.za", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.se", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.ch", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo.co.uk", "/", "http:", "", 4130},
    { 0, 0, 0, 1904, 34, "nintendo-europe.com", "/", "http:", "", 4130},
    -- Zoho SalesIQ Chat
    { 0, 0, 0, 1905, 10, "zoho.com", "/salesiq", "http:", "", 4546},
    -- Zoho Social
    { 0, 0, 0, 1906, 5, "zoho.com", "/social", "http:", "", 4547},
    -- Zoho Connect
    { 0, 0, 0, 1907, 8, "zoho.com", "/connect", "http:", "", 4548},
    -- Zoho Docs
    { 0, 0, 0, 1908, 9, "zoho.com", "/docs", "http:", "", 4549},
    -- Zoho Assist
    { 0, 0, 0, 1909, 9, "zoho.com", "/assist", "http:", "", 4550},

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

