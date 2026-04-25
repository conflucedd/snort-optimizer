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
detection_name: Ask.com
version: 7
description: Search engine.
bundle_description: $VAR1 = {
          'Ask.com' => 'Search engine.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Ask.com Safesearch",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    if (gDetector.CHPMultiCreateApp and gDetector.CHPMultiAddAction) then
    -- uri and cookie and referer
        local handle = gDetector:CHPMultiCreateApp(1371, 4, 1);
        gDetector:CHPMultiAddAction(handle, 1, 1, "www.ask.", 13, "");
        -- remove the unsafe Referer parameter
        gDetector:CHPMultiAddAction(handle, 0, 2, "adt=1", 3, "adt=0");
        gDetector:CHPMultiAddAction(handle, 0, 2, "/web?", 4, "adt=0&");
        -- remove the unsafe URI parameter
        gDetector:CHPMultiAddAction(handle, 0, 3, "adt=1", 3, "adt=0");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/web?", 4, "adt=0&");
        -- remove the unsafe Cookie parameter
        gDetector:CHPMultiAddAction(handle, 0, 4, "adt=1", 3, "adt=0");
        gDetector:CHPMultiAddAction(handle, 0, 4, ";", 4, " adt=0;");
    end
    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
