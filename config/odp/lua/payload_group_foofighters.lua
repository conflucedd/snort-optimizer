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
detection_name: Payload Group "foofighters"
version: 7
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'LiveJournal Post' => 'Making a post on social networking site livejournal.',
          'Microsoft Web Platform Installer' => 'Microsoft Web Platform Installer is a tool to download and setup web development tools based on Microsoft development stack (IIS, SQL Server, .NET Framework, Visual Web Developer, etc).',
          'Synology DSM' => 'Synology is a Network Attached Storage (NAS) appliances running Synology\'s DSM Software.',
          'Mail.ru Attachment' => 'Attaching a file to an email on mail.ru.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_foofighters",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Microsoft  Web platform Installer
    { 0, 0, 0, 1854, 6, "microsoft.com", "/web/handlers/WebPI.ashx?command=", "http:", "", 4081},

    -- Synology DSM
    { 0, 0, 0, 1855, 9, "keymaker.synology.com", "/VERSION", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "keymaker.synology.com", "/keyring", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "keymaker.synology.com", "/keyinfo-sys", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "update.synology.com", "/updatesynohdpack/getSynohdpack.php", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "download.synology.com", "/airprint/DSM", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "www.synology.com", "/dsm/cgi/help/?action=", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "checkip.synology.com", "/", "http:", "", 4089},
    { 0, 0, 0, 1855, 9, "checkipv6.synology.com", "/", "http:", "", 4089},

    -- LiveJournal Post
    { 0, 0, 0, 1856, 5, "livejournal.com", "/update.bml", "http:", "", 4090},

    -- Mail.ru attachment
    { 0, 0, 0, 1857, 4, "e.mail.ru", "/cgi-bin/attach_upload2", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "mail.ru", "attach", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "attachmail.ru", "/", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "e.mail.ru", "/api/v1/messages/attaches", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "mail.ru", "/api-proxy/cloud/v1/folder", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "docs.mail.ru", "/preview", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "docs.mail.ru", "getattach", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "cloud.mail.ru", "/thumb", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "apf.mail.ru", "/", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "e.mail.ru", "/cgi-bin/filesearch", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "an.yandex.ru", "/count", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "stat.radar.imgsmail.ru", "attach", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "stat.radar.imgsmail.ru", "add", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "stat.radar.imgsmail.ru", "upload", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "stat.radar.imgsmail.ru", "cloud", "http:", "", 4091},
    { 0, 0, 0, 1857, 4, "gstat.imgsmail.ru", "/gstat", "http:", "", 4091},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Microsoft Web Platform Installer
    gDetector:addHttpPattern(2, 5, 0, 507, 23, 0, 0, "Platform-Installer/", 4081, 1)
    gDetector:addHttpPattern(2, 5, 0, 507, 23, 0, 0, "WPILauncher/", 4081, 1)

    -- Synology DSM
    gDetector:addHttpPattern(2, 5, 0, 508, 21, 0, 0, "Synology-", 4089, 1)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end
    return gDetector;
end

function DetectorClean()

end
