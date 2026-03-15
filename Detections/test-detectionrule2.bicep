extension MicrosoftSecurity

// targetScope = 'tenant'

resource detectionRule 'Microsoft.Security/detectionRules@2026-01-01-preview' = {
  displayName: 'test bicep detection rule2'
  isEnabled: true
  queryCondition: {
    queryText: 'DeviceEvents\r\n| take 2'
  }
  schedule: {
    period: '24H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'test bicep detection rule 2'
      description: 'test bicep detection rule'
      severity: 'medium'
      category: 'Exfiltration'
      recommendedActions: 'test bicep detection rule 2'
      mitreTechniques: []
      impactedAssets: [
        {
          '@odata.type': '#microsoft.graph.security.impactedDeviceAsset'
          identifier: 'deviceName'
        }
        {
          '@odata.type': '#microsoft.graph.security.impactedDeviceAsset'
          identifier: 'remoteDeviceName'
        }
        {
          '@odata.type': '#microsoft.graph.security.impactedUserAsset'
          identifier: 'accountSid'
        }
        {
          '@odata.type': '#microsoft.graph.security.impactedMailboxAsset'
          identifier: 'initiatingProcessAccountUpn'
        }
      ]
    }
    responseActions: [
      {
        '@odata.type': '#microsoft.graph.security.stopAndQuarantineFileResponseAction'
        identifier: 'deviceId,initiatingProcessSHA1'
      }
    ]
  }
}
