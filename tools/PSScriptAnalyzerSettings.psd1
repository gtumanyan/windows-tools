@{

    IncludeRules = @('PSAvoidDefaultValueSwitchParameter',
        'PSMisleadingBacktick',
        'PSMissingModuleManifestField',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSShouldProcess',
        'PSUseApprovedVerbs',
        'PSAvoidUsingCmdletAliases',
        'PSUseDeclaredVarsMoreThanAssignments')

    Rules        = @{
        PSAvoidUsingCmdletAliases = @{
            AllowList = @("iex", "irm")
        }
    }
}