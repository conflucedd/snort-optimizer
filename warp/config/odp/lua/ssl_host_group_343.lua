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
detection_name: SSL Group "343"
version: 20
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Dogpile' => 'Search engine aggregator.',
          'Vagrant' => 'Tool for building and managing virtual machine environments in a single flow.',
          'Firebase Crashlytics' => 'A crash reporting solution.',
          'Tamil Rockers' => 'Online store for pirated South Indian movies.',
          'Firefox Update' => 'Firefox Software Update.',
          'Daum Mail' => 'Daum webmail.',
          'Splunk' => 'System log aggregator.',
          'Asia Times Online' => 'Web Portal for news update.',
          'Google Meet' => 'Video communication service developed by Google.',
          'Epsilon' => 'Per-click advertising services.',
          'Waze' => 'GPS navigation software app and a subsidiary of Google.',
          'Sizmek Ad Suite' => 'Online ad network.',
          'Hyves' => 'Dutch social networking site.',
          'Philips Hue' => 'Remote controller for wireless light effects.',
          'Insight' => 'Computer and electronic products retailer.',
          'Duo Security' => 'A user-centric access security platform that provides two-factor authentication, endpoint security, remote access solutions and a subsidiary of Cisco.',
          'YouTubeMp3' => 'An online service for converting videos to mp3.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_343",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Asia Times Online
    {0, 1488, 'asiatimes.com', },
    -- Tamil Rockers
    {0, 4295, 'tamilrockers.co.nz', },
    -- YouTubeMp3
    {0, 4384, 'ytmp3.cc', },
    {0, 4384, 'youtubemp3.us', },
    {0, 4384, 'youtubemp3.to', },
    {0, 4384, 'ytmp3.ru', },
    {0, 4384, 'youtubemp3.today', },
    {0, 4384, 'youtubemp3.cloud', },
    -- Epsilon
    {0, 2412, 'epsilon.com', },
    -- Sizmek Ad Suite
    {0, 2464, 'sizmek.com', },
    -- Hyves
    {0, 2608, 'hyvesgames.nl', },
    -- Firebase Crashlytics
    {0, 3969, 'firebase.google.com', },
    {0, 3969, 'crashlytics.com', },
    -- Insight
    {0, 1075, 'insight.com', },
    -- Dogpile
    {0, 2804, 'dogpile.com', },
    -- Waze
    {0, 4650, 'waze.com', },
    -- Vagrant
    {0, 4651, 'vagrantup.com', },
    {0, 4651, 'vagrantcloud.com', },
    -- Google Meet
    {0, 4652, 'meet.google.com', },
    -- Duo Security
    {0, 4648, 'duosecurity.com', },
    {0, 4648, 'duo.com', },
    -- Firefox Update
    {0, 4649, 'download-installer.cdn.mozilla.net', },
    {0, 4649, 'download.mozilla.org', },
    -- Philips Hue
    {0, 2011, 'huedatastore.com', },
    -- Splunk
    {0, 2037, 'splunk.com', },
    {0, 2037, 'splunkcloud.com', },
    -- Daum Mail
    {0, 4055, 'mail.daum.net', },
    {0, 4055, 'mail1.daumcdn.net', },
}

gSSLCnamePatternList = {

    -- Epsilon
    {0, 2412, 'epsilon.com', },
    -- Insight
    {0, 1075, 'insight.com', },
    -- Waze
    {0, 4650, 'waze.com', },
    -- Vagrant
    {0, 4651, 'vagrantup.com', },
    -- Duo Security
    {0, 4648, 'duosecurity.com', },
    -- Splunk
    {0, 2037, 'splunk.com', },
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

