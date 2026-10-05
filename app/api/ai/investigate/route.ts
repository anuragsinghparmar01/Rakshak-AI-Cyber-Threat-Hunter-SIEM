import { GoogleGenAI, Type } from '@google/genai';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
    const title = String(body.title || 'Security Incident');
    const severity = String(body.severity || 'Critical');
    const confidence = Number(body.confidence || 95);
    const events = Array.isArray(body.events) ? body.events : [];
    const affectedHosts = Array.isArray(body.affectedHosts)
      ? body.affectedHosts
      : [];
    const mitreTechniques = Array.isArray(body.mitreTechniques)
      ? body.mitreTechniques
      : [];

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

    const prompt = `You are Rakshak AI Threat Investigator, a senior Tier-3 SOC and Explainable AI (XAI) forensic engine.
Analyze the following security incident and its normalized log evidence, and produce a structured, evidence-backed incident investigation report.

Incident Title: ${title}
Severity: ${severity} | Confidence: ${confidence}%
Affected Hosts: ${affectedHosts.join(', ')}
MITRE ATT&CK Techniques: ${mitreTechniques.join(', ')}

Normalized Log Evidence:
${JSON.stringify(events, null, 2)}

Requirements:
1. Summarize the incident in clear, plain English suitable for both SOC analysts and executive stakeholders.
2. Explain specifically which events triggered the alert and why each is suspicious (cite exact event IDs).
3. Reconstruct a chronological incident timeline.
4. Detail affected assets and scope.
5. Suggest concrete, prioritized investigation and containment steps.
6. Provide an Explainable AI (XAI) reasoning statement detailing how rule triggers, UEBA baseline deviations, and asset criticality combine.
7. Explicitly state limitations and epistemic uncertainties (e.g., encrypted payload contents, potential false-positive edge cases, missing telemetry).`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            plainEnglishSummary: {
              type: Type.STRING,
              description: 'Plain-English summary of the incident.',
            },
            triggeringEventsExplanation: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  eventId: { type: Type.STRING },
                  timestamp: { type: Type.STRING },
                  whatHappened: { type: Type.STRING },
                  whySuspicious: { type: Type.STRING },
                },
                required: [
                  'eventId',
                  'timestamp',
                  'whatHappened',
                  'whySuspicious',
                ],
              },
            },
            chronologicalTimeline: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  step: { type: Type.INTEGER },
                  timestamp: { type: Type.STRING },
                  stage: { type: Type.STRING },
                  asset: { type: Type.STRING },
                  actorOrIp: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: [
                  'step',
                  'timestamp',
                  'stage',
                  'asset',
                  'actorOrIp',
                  'description',
                ],
              },
            },
            affectedAssetsAndScope: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  asset: { type: Type.STRING },
                  criticality: { type: Type.STRING },
                  impactSummary: { type: Type.STRING },
                },
                required: ['asset', 'criticality', 'impactSummary'],
              },
            },
            suggestedInvestigationSteps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            explainableAiReasoning: {
              type: Type.STRING,
            },
            limitationsAndUncertainties: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
          },
          required: [
            'plainEnglishSummary',
            'triggeringEventsExplanation',
            'chronologicalTimeline',
            'affectedAssetsAndScope',
            'suggestedInvestigationSteps',
            'explainableAiReasoning',
            'limitationsAndUncertainties',
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');

    return NextResponse.json({
      report: {
        generatedAt: new Date().toISOString(),
        modelUsed: 'gemini-3.8-flash (Server-Side XAI)',
        ...parsed,
      },
    });
  } catch (error: unknown) {
    const errMsg = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      {
        error: errMsg,
        fallbackNotice:
          'Synthesized deterministic XAI forensic report from normalized log evidence.',
      },
      { status: 200 }
    );
  }
}
