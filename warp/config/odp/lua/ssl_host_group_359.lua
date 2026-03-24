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
detection_name: SSL Group "359"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Notion' => 'Project management and note-taking software platform.',
          'Wrike' => 'Project management software.',
          'Jabra' => 'Brand specializing in audio equipment and videoconference systems.',
          'Termius' => 'SSH client.',
          'Calendly' => 'Calendar and group scheduling software application.',
          'Grafana' => 'Multi-platform open source analytics and interactive visualization web application.',
          'Tabnine' => 'Code assistant plugin for major IDEs.',
          'Postman' => 'API platform for developers to design, build, test and iterate their APIs.',
          'DeepL Translator' => 'Translation service.',
          'BoxCryptor' => 'File Encryption software.',
          '1Password' => 'Password management application.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_359",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Postman
    {0, 6268, 'postman.com', },
    {0, 6268, 'postman.co', },
    {0, 6268, 'getpostman.com', },
    {0, 6268, 'postmanlabs.com', },
    {0, 6268, 'pstmn.io', },
    {0, 6268, 'bi.pst.tech', },
    -- DeepL Translator
    {0, 6269, 'deepl.com', },
    -- Notion
    {0, 6270, 'notion.com', },
    {0, 6270, 'notion.so', },
    {0, 6270, 'makenotion.com', },
    {0, 6270, 'notion.site', },
    -- Grafana
    {0, 6271, 'grafana.com', },
    {0, 6271, 'grafana.net', },
    -- Jabra
    {0, 6272, 'jabra.com', },
    -- Termius
    {0, 6273, 'termius.com', },
    -- BoxCryptor
    {0, 6274, 'boxcryptor.com', },
    {0, 6274, 'secomba.com', },
    -- Wrike
    {0, 6275, 'wrike.com', },
    -- Calendly
    {0, 6276, 'calendly.com', },
    -- Tabnine
    {0, 6277, 'tabnine.com', },
    -- 1Password
    {0, 6278, '1password.com', },
    {0, 6278, '1passwordservices.com', },
    {0, 6278, 'agilebits.com', },
}

gSSLCnamePatternList = {
    -- Postman
    {0, 6268, 'postman.com', },
    {0, 6268, 'postman.co', },
    {0, 6268, 'getpostman.com', },
    {0, 6268, 'postmanlabs.com', },
    {0, 6268, 'pstmn.io', },
    {0, 6268, 'bi.pst.tech', },
    -- DeepL Translator
    {0, 6269, 'deepl.com', },
    -- Notion
    {0, 6270, 'notion.com', },
    {0, 6270, 'notion.so', },
    {0, 6270, 'makenotion.com', },
    {0, 6270, 'notion.site', },
    -- Grafana
    {0, 6271, 'grafana.com', },
    {0, 6271, 'grafana.net', },
    -- Jabra
    {0, 6272, 'jabra.com', },
    -- Termius
    {0, 6273, 'termius.com', },
    -- BoxCryptor
    {0, 6274, 'boxcryptor.com', },
    {0, 6274, 'secomba.com', },
    -- Wrike
    {0, 6275, 'wrike.com', },
    -- Calendly
    {0, 6276, 'calendly.com', },
    -- Tabnine
    {0, 6277, 'tabnine.com', },
    -- 1Password
    {0, 6278, '1password.com', },
    {0, 6278, '1passwordservices.com', },
    {0, 6278, 'agilebits.com', },
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
