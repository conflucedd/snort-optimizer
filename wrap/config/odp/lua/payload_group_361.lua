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
detection_name: Payload Group "361"
version: 2
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Pearson' => 'Online learning provider.',
          'Visa.com' => 'Credit card and digital payment services.',
          'Fandom' => 'Entertainment news, blogs, and wikis.',
          'Pearson Online Academy' => 'Online school in the US, grades K-12.',
          'Pearson VUE' => 'Computer-based certification tests.',
          'Tradestation' => 'Trading and brokerage service.',
          'Zoho CRM' => 'Zoho CRM platform for sales and marketing.',
          'Forcepoint' => 'Network and cloud security software.',
          'Savvas' => 'Online education company.',
          'Keap' => 'Sales, marketing, and CRM platform.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_361",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Tradestation
    { 0, 0, 0, 4615, 1, "tradestation.com", "/", "http:", "", 7346},
    -- Pearson
    { 0, 0, 0, 4616, 1, "pearson.com", "/", "http:", "", 7348},
    -- Pearson VUE
    { 0, 0, 0, 4617, 1, "pearsonvue.com", "/", "http:", "", 7349},
    -- Pearson Online Academy
    { 0, 0, 0, 4618, 1, "classroom.pearson.com", "/", "http:", "", 7350},
    -- Savvas
    { 0, 0, 0, 4619, 1, "savvas.com", "/", "http:", "", 7351},
    -- Fandom
    { 0, 0, 0, 4620, 1, "fandom.com", "/", "http:", "", 7352},
    -- Keap
    { 0, 0, 0, 4621, 1, "keap.com", "/", "http:", "", 7353},
    -- Forcepoint
    { 0, 0, 0, 4622, 1, "forcepoint.com", "/", "http:", "", 7354},
    -- Visa.com
    { 0, 0, 0, 4623, 1, "visa.com", "/", "http:", "", 7355},
    -- Zoho CRM
    { 0, 0, 0, 4624, 1, "crm.zoho.com", "/", "http:", "", 7356},
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
