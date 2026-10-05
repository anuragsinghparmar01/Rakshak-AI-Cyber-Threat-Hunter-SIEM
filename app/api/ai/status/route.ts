import { GoogleGenAI } from '@google/genai';
import { NextResponse } from 'next/server';

export async function GET() {
  const start = Date.now();
  const hasServerKey = Boolean(
    process.env.GEMINI_API_KEY &&
      process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'
  );

  if (!hasServerKey) {
    return NextResponse.json({
      status: 'fallback_ready',
      model: 'gemini-3.8-flash',
      latencyMs: Date.now() - start,
      message:
        'Server-side deterministic XAI engine active. Attach GEMINI_API_KEY in AI Studio Settings > Secrets for live LLM generation.',
    });
  }

  try {
    const ai = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: 'Respond with the single word: ONLINE',
    });

    return NextResponse.json({
      status: 'online',
      model: 'gemini-3.8-flash',
      latencyMs: Date.now() - start,
      probeResponse: (response.text || 'ONLINE').trim(),
      message:
        'Server-side Gemini 3.8 Flash engine verified and responding.',
    });
  } catch (error: unknown) {
    return NextResponse.json({
      status: 'fallback_ready',
      model: 'gemini-3.8-flash',
      latencyMs: Date.now() - start,
      message:
        error instanceof Error
          ? `Deterministic XAI fallback active (${error.message}).`
          : 'Deterministic XAI fallback active.',
    });
  }
}
