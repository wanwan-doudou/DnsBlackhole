export interface QueryLogPaginationState {
  totalPages: number;
  start: number;
  end: number;
  previousDisabled: boolean;
  nextDisabled: boolean;
}

export function totalQueryLogPages(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

export function queryLogPaginationState(
  page: number,
  total: number,
  pageSize: number,
  loading: boolean,
): QueryLogPaginationState {
  const totalPages = totalQueryLogPages(total, pageSize);
  return {
    totalPages,
    start: total === 0 ? 0 : (page - 1) * pageSize + 1,
    end: Math.min(total, page * pageSize),
    previousDisabled: loading || page <= 1,
    nextDisabled: loading || page >= totalPages,
  };
}
