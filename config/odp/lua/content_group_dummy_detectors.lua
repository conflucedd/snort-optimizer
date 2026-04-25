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
detection_name: Content Group "Dummy Detectors"
version: 5
description: Dummy detector group, for C/C++ detectors built into snort.
bundle_description: $VAR1 = {
          'SMBv3-unencrypted' => 'Server Message Block version 3, more recent SMB dialects including SMB 3.0, SMB 3.0.1, and SMB 3.1.1.',
          'SMBv3-encrypted' => 'Server Message Block version 3, encrypted traffic.',
          'SMBv1' => 'Server Message Block version 1, a set of early SMB dialects including SMB, SMB1, and CIFS.',
          'SMBv2' => 'Server Message Block version 2. This set of SMB dialects includes SMB 2.0 and SMB 2.1.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon                                                                           
                                                                                                    
DetectorPackageInfo = {                                                                             
    name = "content_group_dummy_detectors",                                                                  
    proto =  DC.ipproto.tcp,                                                                        
    client = {                                                                                      
        init =  'DetectorInit',                                                                     
        clean =  'DetectorClean',                                                                   
        minimum_matches =  1                                                                        
    }                                                                                               
}        

gSfAppIdSMBv1 = 4645
gSfAppIdSMBv2 = 4646
gSfAppIdSMBv3_encrypted = 4647
gSfAppIdSMBv3_unencrypted = 4665

function DetectorInit( detectorInstance)
end

function DetectorValidator()
end

function DetectorFini()
end

