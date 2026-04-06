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
detection_name: SSL Group "foofighters"
version: 11
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Synology DSM' => 'Synology is a Network Attached Storage (NAS) appliances running Synology\'s DSM Software.',
          'Google Drive' => 'A free office suite and cloud storage system hosted by Google.',
          'Webex Teams' => 'Webex Teams is a collaboration tool with various clients (Windows, OS X, Android, Windows Mobile, iPad, iPhone, Web) for messages, calls, meetings, etc.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_foofighters",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Webex Teams
    { 1, 4080, 'ciscospark.com' },
    { 1, 4080, 'wbx2.com' },
    { 1, 4080, 'idbroker.webex.com' },
    { 1, 4080, 'teams.webex.com' },
    -- Synology DSM
    { 0, 4089, 'synology.com' },

    -- Google Drive
    { 0, 180, 'upload.video.google.com' },
    { 0, 180, 'googledrive.com' },
    { 0, 180, 'drive.google.com' },
    { 0, 180, 'drive-thirdparty.googleusercontent.com' },
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

