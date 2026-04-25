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
detection_name: Payload Group "344"
version: 4
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Google Meet' => 'Video communication service developed by Google.',
          'Waze' => 'GPS navigation software app and a subsidiary of Google.',
          'Vocera' => 'Network-based software systems which provide voice communication.',
          'Splunk' => 'System log aggregator.',
          'Firefox Update' => 'Firefox Software Update.',
          'Vagrant' => 'Tool for building and managing virtual machine environments in a single flow.',
          'Duo Security' => 'A user-centric access security platform that provides two-factor authentication, endpoint security, remote access solutions and a subsidiary of Cisco.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_344",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Waze
    { 0, 0, 0, 1970, 1, "waze.com", "/", "http:", "", 4650},
    -- Vagrant
    { 0, 0, 0, 1971, 1, "vagrantup.com", "/", "http:", "", 4651},
    { 0, 0, 0, 1971, 1, "vagrantcloud.com", "/", "http:", "", 4651},
    -- Google Meet
    { 0, 0, 0, 1972, 1, "meet.google.com", "/", "http:", "", 4652},
    -- Duo Security
    { 0, 0, 0, 1976, 1, "duosecurity.com", "/", "http:", "", 4648},
    { 0, 0, 0, 1976, 1, "duo.com", "/", "http:", "", 4648},
    -- Firefox Update
    { 0, 0, 0, 1977, 1, "download-installer.cdn.mozilla.net", "/", "http:", "", 4649},
    { 0, 0, 0, 1977, 1, "download.mozilla.org", "/", "http:", "", 4649},
    -- Splunk
    { 0, 0, 0, 1978, 1, "splunk.com", "/", "http:", "", 2037},
    { 0, 0, 0, 1978, 1, "splunkcloud.com", "/", "http:", "", 2037},
    -- Vocera
    { 0, 0, 0, 1982, 1, "vocera.com", "/", "http:", "", 4653},
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

