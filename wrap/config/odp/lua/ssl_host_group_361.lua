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
detection_name: SSL Group "361"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Fandom' => 'Entertainment news, blogs, and wikis.',
          'Visa.com' => 'Credit card and digital payment services.',
          'Pearson Online Academy' => 'Online school in the US, grades K-12.',
          'Savvas' => 'Online education company.',
          'Pearson' => 'Online learning provider.',
          'Pearson VUE' => 'Computer-based certification tests.',
          'Tradestation' => 'Trading and brokerage service.',
          'Keap' => 'Sales, marketing, and CRM platform.',
          'Forcepoint' => 'Network and cloud security software.',
          'Zoho CRM' => 'Zoho CRM platform for sales and marketing.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_361",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Tradestation
    {0, 7346, 'tradestation.com'},
    -- Pearson
    {0, 7348, 'pearson.com'},
    -- Pearson VUE
    {0, 7349, 'pearsonvue.com'},
    -- Pearson Online Academy
    {0, 7350, 'classroom.pearson.com'},
    -- Savvas
    {0, 7351, 'savvas.com'},
    -- Fandom
    {0, 7352, 'fandom.com'},
    -- Keap
    {0, 7353, 'keap.com'},
    -- Forcepoint
    {0, 7354, 'forcepoint.com'},
    -- Visa.com
    {0, 7355, 'visa.com'},
    -- Zoho CRM
    {0, 7356, 'crm.zoho.com'},
}

gSSLCnamePatternList = {
    -- Tradestation
    {0, 7346, 'tradestation.com'},
    -- Pearson
    {0, 7348, 'pearson.com'},
    -- Pearson VUE
    {0, 7349, 'pearsonvue.com'},
    -- Pearson Online Academy
    {0, 7350, 'classroom.pearson.com'},
    -- Savvas
    {0, 7351, 'savvas.com'},
    -- Fandom
    {0, 7352, 'fandom.com'},
    -- Keap
    {0, 7353, 'keap.com'},
    -- Forcepoint
    {0, 7354, 'forcepoint.com'},
    -- Visa.com
    {0, 7355, 'visa.com'},
    -- Zoho CRM
    {0, 7356, 'crm.zoho.com'},
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
