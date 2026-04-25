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
detection_name: Payload Group "359"
version: 1
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Jabra' => 'Brand specializing in audio equipment and videoconference systems.',
          'Wrike' => 'Project management software.',
          '1Password' => 'Password management application.',
          'Postman' => 'API platform for developers to design, build, test and iterate their APIs.',
          'Calendly' => 'Calendar and group scheduling software application.',
          'Grafana' => 'Multi-platform open source analytics and interactive visualization web application.',
          'DeepL Translator' => 'Translation service.',
          'Notion' => 'Project management and note-taking software platform.',
          'Tabnine' => 'Code assistant plugin for major IDEs.',
          'Termius' => 'SSH client.',
          'BoxCryptor' => 'File Encryption software.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_359",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Postman
    { 0, 0, 0, 3558, 1, "postman.com", "/", "http:", "", 6268},
    { 0, 0, 0, 3558, 1, "postman.co", "/", "http:", "", 6268},
    { 0, 0, 0, 3558, 1, "getpostman.com", "/", "http:", "", 6268},
    { 0, 0, 0, 3558, 1, "postmanlabs.com", "/", "http:", "", 6268},
    { 0, 0, 0, 3558, 1, "pstmn.io", "/", "http:", "", 6268},
    { 0, 0, 0, 3558, 1, "bi.pst.tech", "/", "http:", "", 6268},
    -- DeepL Translator
    { 0, 0, 0, 3559, 1, "deepl.com", "/", "http:", "", 6269},
    -- Notion
    { 0, 0, 0, 3560, 1, "notion.com", "/", "http:", "", 6270},
    { 0, 0, 0, 3560, 1, "notion.so", "/", "http:", "", 6270},
    { 0, 0, 0, 3560, 1, "makenotion.com", "/", "http:", "", 6270},
    { 0, 0, 0, 3560, 1, "notion.site", "/", "http:", "", 6270},
    -- Grafana
    { 0, 0, 0, 3561, 1, "grafana.com", "/", "http:", "", 6271},
    { 0, 0, 0, 3561, 1, "grafana.net", "/", "http:", "", 6271},
    -- Jabra
    { 0, 0, 0, 3562, 1, "jabra.com", "/", "http:", "", 6272},
    -- Termius
    { 0, 0, 0, 3563, 1, "termius.com", "/", "http:", "", 6273},
    -- BoxCryptor
    { 0, 0, 0, 3564, 1, "boxcryptor.com", "/", "http:", "", 6274},
    { 0, 0, 0, 3564, 1, "secomba.com", "/", "http:", "", 6274},
    -- Wrike
    { 0, 0, 0, 3565, 1, "wrike.com", "/", "http:", "", 6275},
    -- Calendly
    { 0, 0, 0, 3566, 1, "calendly.com", "/", "http:", "", 6276},
    -- Tabnine
    { 0, 0, 0, 3567, 1, "tabnine.com", "/", "http:", "", 6277},
    --  1Password
    { 0, 0, 0, 3568, 1, "1password.com", "/", "http:", "", 6278},
    { 0, 0, 0, 3568, 1, "1passwordservices.com", "/", "http:", "", 6278},
    { 0, 0, 0, 3568, 1, "agilebits.com", "/", "http:", "", 6278},
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
