import { query } from "./dom";
import { escapeHtml, formatCount, formatSparkBucketLabel } from "./format";
import type { ChartPoint, HistoryPoint, TrafficBucket } from "./types";

export function buildTrafficSeries(
  buckets: TrafficBucket[] | undefined,
  field: "queries" | "blocked",
  windowHours: number,
): HistoryPoint[] {
  const pointCount = 48;
  const latestMinute = Math.floor(Date.now() / 60000);
  const windowMinutes = Math.max(pointCount, Math.ceil(windowHours * 60));
  const bucketMinutes = Math.max(1, Math.ceil(windowMinutes / pointCount));
  const firstMinute = latestMinute - bucketMinutes * pointCount + 1;
  const values = Array.from({ length: pointCount }, (_, index) => {
    const minute = firstMinute + index * bucketMinutes;
    return {
      index,
      value: 0,
      label: formatSparkBucketLabel(minute, bucketMinutes),
    };
  });

  for (const bucket of buckets ?? []) {
    const index = Math.floor((bucket.minute - firstMinute) / bucketMinutes);
    if (index >= 0 && index < pointCount) {
      values[index].value += bucket[field];
    }
  }

  return values;
}

export function renderSparkline(selector: string, series: HistoryPoint[]): void {
  const line = query<SVGPathElement>(selector);
  const svg = line.ownerSVGElement;
  if (!svg) {
    return;
  }

  const area = svg.querySelector<SVGPathElement>(".spark-area");
  if (!area) {
    return;
  }

  const width = 260;
  const baseline = 72;
  const top = 8;
  const maxValue = Math.max(...series.map((point) => point.value), 1);
  const coords = series.map<ChartPoint>((point, index) => {
    const x = series.length === 1 ? width : (index / (series.length - 1)) * width;
    const y = baseline - (point.value / maxValue) * (baseline - top);
    return { ...point, x, y };
  });
  const linePath = buildMonotonePath(coords);
  const areaPath = buildAreaPath(coords, baseline);

  if (line.getAttribute("d") !== linePath) {
    line.setAttribute("d", linePath);
  }
  if (area.getAttribute("d") !== areaPath) {
    area.setAttribute("d", areaPath);
  }

  bindSparklineHover(svg, coords, width);
}

function buildAreaPath(points: ChartPoint[], baseline: number): string {
  const linePath = buildMonotonePath(points);
  if (!linePath || points.length === 0) {
    return "";
  }

  const first = points[0];
  const last = points[points.length - 1];
  return `${linePath} L ${last.x.toFixed(1)} ${baseline.toFixed(1)} L ${first.x.toFixed(1)} ${baseline.toFixed(1)} Z`;
}

function buildMonotonePath(points: ChartPoint[]): string {
  if (points.length === 0) {
    return "";
  }
  if (points.length === 1) {
    const point = points[0];
    return `M ${point.x.toFixed(1)} ${point.y.toFixed(1)}`;
  }

  const slopes = points.slice(0, -1).map((point, index) => {
    const next = points[index + 1];
    return (next.y - point.y) / (next.x - point.x || 1);
  });
  const tangents = points.map((_, index) => {
    if (index === 0) {
      return slopes[0];
    }
    if (index === points.length - 1) {
      return slopes[slopes.length - 1];
    }

    const prev = slopes[index - 1];
    const next = slopes[index];
    return prev * next <= 0 ? 0 : (prev + next) / 2;
  });

  let path = `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  for (let index = 0; index < points.length - 1; index += 1) {
    const current = points[index];
    const next = points[index + 1];
    const dx = next.x - current.x;
    const cp1x = current.x + dx / 3;
    const cp1y = current.y + (tangents[index] * dx) / 3;
    const cp2x = next.x - dx / 3;
    const cp2y = next.y - (tangents[index + 1] * dx) / 3;
    path += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${next.x.toFixed(1)} ${next.y.toFixed(1)}`;
  }

  return path;
}

function bindSparklineHover(svg: SVGSVGElement, coords: ChartPoint[], width: number): void {
  const guide = svg.querySelector<SVGLineElement>(".spark-guide");
  const point = svg.querySelector<SVGCircleElement>(".spark-point");
  const tooltipId = svg.dataset.tooltip;
  const tooltip = tooltipId ? query<HTMLDivElement>(`#${tooltipId}`) : null;
  if (!guide || !point || !tooltip) {
    return;
  }

  const hideTooltip = () => {
    guide.classList.add("hidden");
    point.classList.add("hidden");
    tooltip.classList.add("hidden");
  };

  svg.onpointerleave = hideTooltip;
  svg.onpointermove = (event) => {
    if (coords.length === 0) {
      hideTooltip();
      return;
    }

    const rect = svg.getBoundingClientRect();
    const relativeX = clamp(((event.clientX - rect.left) / rect.width) * width, 0, width);
    const nearest = coords.reduce((best, current) =>
      Math.abs(current.x - relativeX) < Math.abs(best.x - relativeX) ? current : best,
    );

    guide.setAttribute("x1", nearest.x.toFixed(1));
    guide.setAttribute("x2", nearest.x.toFixed(1));
    point.setAttribute("cx", nearest.x.toFixed(1));
    point.setAttribute("cy", nearest.y.toFixed(1));
    tooltip.innerHTML = `<strong>${formatCount(nearest.value)}</strong><span>${escapeHtml(nearest.label)}</span>`;

    // 先显示再测量：.hidden 为 display:none 时取不到 tooltip 的真实尺寸
    guide.classList.remove("hidden");
    point.classList.remove("hidden");
    tooltip.classList.remove("hidden");

    const host = svg.parentElement;
    const hostRect = host?.getBoundingClientRect();
    if (!hostRect) {
      return;
    }
    const svgRect = svg.getBoundingClientRect();
    const pointLeft = svgRect.left - hostRect.left + (nearest.x / width) * svgRect.width;
    const pointTop = svgRect.top - hostRect.top + (nearest.y / 78) * svgRect.height;

    // tooltip 位于 overflow:hidden 的卡片内，按其真实尺寸把锚点收敛到卡片范围内，避免溢出被裁切。
    // CSS transform 为 translate(-50%, -105%)：水平相对锚点居中，垂直向上偏移自身高度的 105%
    const margin = 8;
    const halfWidth = tooltip.offsetWidth / 2;
    const tooltipHeight = tooltip.offsetHeight;
    const minLeft = halfWidth + margin;
    const maxLeft = Math.max(minLeft, hostRect.width - halfWidth - margin);
    const minTop = tooltipHeight * 1.05 + margin;
    const maxTop = Math.max(minTop, hostRect.height - tooltipHeight * 0.05 - margin);
    tooltip.style.left = `${clamp(pointLeft, minLeft, maxLeft)}px`;
    tooltip.style.top = `${clamp(pointTop, minTop, maxTop)}px`;
  };
}

export function runtimeWindowHours(startedAt: number | null): number {
  if (!startedAt) {
    return 1;
  }
  const elapsedSeconds = Math.max(60, Date.now() / 1000 - startedAt);
  return Math.max(1, Math.ceil(elapsedSeconds / 3600));
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}
