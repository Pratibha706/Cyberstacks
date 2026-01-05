import { WebSecurityScannerClient } from '@google-cloud/web-security-scanner';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL missing' });

  const client = new WebSecurityScannerClient();
  const PROJECT_ID = process.env.GCP_PROJECT_ID;

  try {
    const [scanConfig] = await client.createScanConfig({
      parent: `projects/${PROJECT_ID}`,
      scanConfig: { displayName: 'CyberStack Scan', startingUrls: [url] }
    });

    const [scanRun] = await client.startScanRun({ name: scanConfig.name });

    // Return scanRun name (ID) immediately
    res.status(200).json({ scanRunId: scanRun.name, message: 'Scan started' });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
