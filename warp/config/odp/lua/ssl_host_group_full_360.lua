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
detection_name: SSL Group Full "360"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Tesla' => 'Sustainable energy services for a world powered by solar energy, running on batteries and transported by electric vehicles.',
          'Disney Plus' => 'Disney+ is a video on-demand streaming subscription.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_full_360",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Tesla
    {0, 7338, 'tesla.services', },
    {0, 7338, 'teslamotors.com', },
    {0, 7338, 'tesla-hermes-snapshot-motors.s3-us-west-2.amazonaws.com', },
    {0, 7338, 'tesla-hermes-snapshot-energy.s3-us-west-2.amazonaws.com', },
    {0, 7338, 'teslaenergy.services', },
    {0, 7338, 'tesla-hermes-snapshot.s3.us-west-2.amazonaws.com', },
    -- Disney Plus
    {0, 4617, 'dssott.qwilted-cds.cqloud.com', },
    {0, 4617, 'dssedge.com', },
}

gSSLCnamePatternList = {

    -- Tesla
    {0, 7338, 'tesla.services', },
    {0, 7338, 'teslamotors.com', },
    {0, 7338, 'tesla-hermes-snapshot-motors.s3-us-west-2.amazonaws.com', },
    {0, 7338, 'tesla-hermes-snapshot-energy.s3-us-west-2.amazonaws.com', },
    {0, 7338, 'teslaenergy.services', },
    {0, 7338, 'tesla-hermes-snapshot.s3.us-west-2.amazonaws.com', },
    -- Disney Plus
    {0, 4617, 'dssott.qwilted-cds.cqloud.com', },
    {0, 4617, 'dssedge.com', },
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
