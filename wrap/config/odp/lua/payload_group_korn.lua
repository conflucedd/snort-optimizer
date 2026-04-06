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
detection_name: Payload Group "korn"
version: 18
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Flightradar24' => 'Real-time aircraft flight tracking web service.',
          'Webex Teams' => 'Webex Teams is a collaboration tool with various clients (Windows, OS X, Android, Windows Mobile, iPad, iPhone, Web) for messages, calls, meetings, etc.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'Elephant Drive' => 'Cloud storage service used primarily as an online backup tool.',
          'Hotstar' => 'Video streaming app for Star India.',
          'Windows Media' => 'Windows Multimedia traffic.',
          'AnyDesk' => 'Remote Desktop Access Software.',
          'ZenVPN' => 'VPN/anonymizer app.',
          'Open Drive' => 'Cloud storage and online backup system.',
          'Google Remote Desktop' => 'Online desktop sharing service.',
          'NetSarang' => 'Network connectivity and management tools package.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_korn",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Webex teams
    { 0, 0, 0, 1878, 49, "ciscospark.com", "/", "http:", "", 4080},
    -- Google Remote Desktop
    { 0, 0, 0, 1880, 7, "chrome.google.com", "/remotedesktop", "http:", "", 1665},
    { 0, 0, 0, 1880, 7, "chrome.google.com", "/chrome-remote-desktop", "http:", "", 1665},
    -- Elephant Drive
    { 0, 0, 0, 1881, 9, "elephantdrive.com", "/", "http:", "", 4143},
    { 0, 0, 0, 1881, 9, "seal.starfieldtech.com", "/", "http:", "", 4143},
    { 0, 0, 0, 1881, 9, "bucket1-direct-elephantdrive-com.s3.amazonaws.com", "/", "http:", "", 4143},
    { 0, 0, 0, 1881, 9, "distribution.vaultservices.net", "/Elephant", "http:", "", 4143},
    -- Open Drive
    { 0, 0, 0, 1882, 9, "od.lk", "/", "http:", "", 4144},
    { 0, 0, 0, 1882, 9, "opendrive.com", "/", "http:", "", 4144},
    -- AnyDesk
    { 0, 0, 0, 1883, 8, "anydesk.com", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.de", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.it", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.fr", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.dk", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.pl", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.cz", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.pt", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.se", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.es", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.sk", "/", "http:", "", 4145},
    { 0, 0, 0, 1883, 8, "anydesk.gr", "/", "http:", "", 4145},
    -- NetSarang
    { 0, 0, 0, 1884, 9, "netsarang.com", "/", "http:", "", 4146},
    { 0, 0, 0, 1884, 9, "netsarang.co.kr", "/", "http:", "", 4146},
    -- Showbox
    { 0, 0, 0, 1885, 13, "showboxappdownload.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxappdownloading.com", "/", "http:", "", 4149},
    -- { 0, 0, 0, 1885, 13, "showboxappdownloads.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxappdownload.co", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxdownloadmovies.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showbox.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showbox.org", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxpro.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "apk.com", "/showbox", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "apk.org", "/showbox", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxapp.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "apkmirror.com", "/show-box", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxapk.tips", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxapkandroid.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxapkdl.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxappandroid.com", "/", "http:", "", 4149},
    { 0, 0, 0, 1885, 13, "showboxmoviesonline.com", "/", "http:", "", 4149},
    -- ZenVPN
    { 0, 0, 0, 1886, 46, "zenvpn.net", "/", "http:", "", 4150},
    -- Windows Media
    { 0, 0, 0, 1887, 2, "microsoft.com", "/windowsmedia", "http:", "", 503},
    { 0, 0, 0, 1887, 2, "support.microsoft.com", "windows-media", "http:", "", 503},
    { 0, 0, 0, 1887, 2, "microsoft.com", "windows-media-player", "http:", "", 503},
    { 0, 0, 0, 1887, 2, "windowsmedia.com", "/", "http:", "", 503},
    -- Flightradar24
    { 0, 0, 0, 1888, 16, "flightradar24.com", "/", "http:", "", 4148},
    -- Hotstar
    { 0, 526, 19, 1889, 13, "hotstar.com", "/", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "media0-starag.startv.in", "/", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "media1-starag.startv.in", "/", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "media2-starag.startv.in", "/", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "media1-starag.startv.in", "/thumbs/ANDROID", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "starsports.com/", "/", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "hotstar-sin.gravityrd-services.com", "/", "http:", "", 4153},
    { 0, 526, 19, 1889, 13, "staragvod3-vh.akamaihd.net", "/", "http:", "", 4153},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- NetSarang
    gDetector:addHttpPattern(2, 5, 0, 523, 12, 0, 0, 'TrueUpdate', 4146);
    gDetector:addHttpPattern(2, 5, 0, 523, 12, 0, 0, 'toys::file', 4146);
    -- Showbox
    gDetector:addHttpPattern(2, 5, 0, 524, 19, 0, 0, 'Show Box', 4149);
    gDetector:addHttpPattern(2, 5, 0, 524, 19, 0, 0, 'Lavf', 4149);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
