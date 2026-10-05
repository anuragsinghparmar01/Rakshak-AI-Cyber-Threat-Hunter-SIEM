import { NextRequest, NextResponse } from 'next/server';
import {
  normalizeRawLogBatch,
  deduplicateAndCorrelateLogsToAlerts,
} from '@/lib/detection-engine';
import { INITIAL_ALERTS } from '@/lib/security-data';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const rawText: string = body.rawText || '';

    if (!rawText.trim()) {
      return NextResponse.json(
        { error: 'rawText payload is required for log normalization.' },
        { status: 400 }
      );
    }

    const normalizedLogs = normalizeRawLogBatch(rawText);
    const correlatedAlerts = deduplicateAndCorrelateLogsToAlerts(
      normalizedLogs,
      INITIAL_ALERTS
    );

    return NextResponse.json({
      status: 'ok',
      processedAt: new Date().toISOString(),
      ingestedCount: normalizedLogs.length,
      normalizedLogs,
      totalCorrelatedAlerts: correlatedAlerts.length,
    });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Normalization error';
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
