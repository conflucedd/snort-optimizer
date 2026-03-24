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
detection_name: SSL Group "363"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Ola Cabs' => 'Ola Cabs is an Indian multinational ridesharing platform.',
          'DallE' => 'An AI system that can create realistic images and art from a description in natural language.',
          'ChatGPT' => 'An AI which is trained to follow an instruction in a prompt and provide a detailed response.',
          'CompTIA' => 'IT training and certification vendor.',
          'OpenAI' => 'An American artificial intelligence research laboratory consisting of the non-profit OpenAI Incorporated and its for-profit subsidiary corporation OpenAI Limited Partnership.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_363",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- ChatGPT
    {0, 7358, 'chat.openai.com'},
    {0, 7358, 'auth0.openai.com'},
    -- CompTIA
    {0, 7359, 'comptia.org'},
    -- OpenAI
    {0, 7360, 'openai.com'},
    -- DallE
    {0, 7361, 'labs.openai.com'},
    -- Ola Cabs
    {0, 7362, 'olacabs.com'},
}

gSSLCnamePatternList = {
    -- ChatGPT
    {0, 7358, 'chat.openai.com'},
    {0, 7358, 'auth0.openai.com'},
    -- CompTIA
    {0, 7359, 'comptia.org'},
    -- OpenAI
    {0, 7360, 'openai.com'},
    -- DallE
    {0, 7361, 'labs.openai.com'},
    -- Ola Cabs
    {0, 7362, 'olacabs.com'},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

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