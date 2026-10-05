import { GoogleGenAI, Type } from '@google/genai';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  try {
    const { query, logs = [] } = await req.json();

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
      throw new Error('GEMINI_API_KEY environment secret not yet configured.');
    }

    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const prompt = `You are Rakshak Natural-Language Threat Hunter.
An analyst asked the following threat hunting question:
"${query}"

Available Normalized Security Events:
${JSON.stringify(
  logs.map((l: Record<string, unknown>) => ({
    id: l.id,
    timestamp: l.timestamp,
    host: l.host,
    os: l.os,
    user: l.user,
    sourceIp: l.sourceIp,
    category: l.category,
    eventCode: l.eventCode,
    outcome: l.outcome,
    summary: l.normalizedSummary,
    anomalyScore: l.anomalyScore,
  })),
  null,
  2
)}

Return a JSON object containing:
1. translatedQueryDsl: A formal SIEM/Wazuh correlation query expression representing the user's question.
2. matchedEventIds: Array of event IDs (e.g. ["EVT-9001", "EVT-9005"]) that match the hunt hypothesis.
3. analystNarrative: Clear explanation of the correlated events found and why they answer the analyst's hunt query.
4. mitreMapping: Relevant MITRE ATT&CK Technique ID and name.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            translatedQueryDsl: { type: Type.STRING },
            matchedEventIds: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            analystNarrative: { type: Type.STRING },
            mitreMapping: { type: Type.STRING },
          },
          required: [
            'translatedQueryDsl',
            'matchedEventIds',
            'analystNarrative',
            'mitreMapping',
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    return NextResponse.json({ result: parsed });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ error: errMsg }, { status: 200 });
  }
}
