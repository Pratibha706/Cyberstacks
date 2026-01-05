import { WebSecurityScannerClient } from '@google-cloud/web-security-scanner';

export default async function handler(req, res) {
  const { scanRunId } = req.query;
  if (!scanRunId) return res.status(400).json({ error: 'scanRunId missing' });

  const client = new WebSecurityScannerClient();

  try {
    const [scanRun] = await client.getScanRun({ name: scanRunId });

    if (scanRun.executionState !== 'FINISHED') {
      return res.status(200).json({ status: scanRun.executionState });
    }

    const [findings] = await client.listFindings({ parent: scanRun.name });
    res.status(200).json({ findings });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
