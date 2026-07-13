import { ref, shallowRef, type Ref, type ShallowRef } from "vue";
import { ApiError } from "../api";

export interface AsyncState<T> {
  data: ShallowRef<T | null>;
  error: Ref<ApiError | null>;
  loading: Ref<boolean>;
  succeeded: Ref<boolean>;
  run: () => Promise<void>;
}

/**
 * Wrap an async loader with loading and error state. `run` never
 * throws; failures land in `error` as an ApiError so views can render
 * a clear error surface instead of a blank panel.
 */
export function useAsync<T>(loader: () => Promise<T>): AsyncState<T> {
  const data = shallowRef<T | null>(null);
  const error = ref<ApiError | null>(null);
  const loading = ref<boolean>(false);
  const succeeded = ref<boolean>(false);
  let latestInvocation = 0;

  async function run() {
    const invocation = ++latestInvocation;
    loading.value = true;
    error.value = null;
    succeeded.value = false;
    try {
      const loaded = await loader();
      if (invocation !== latestInvocation) return;
      data.value = loaded;
      succeeded.value = true;
    } catch (e) {
      if (invocation !== latestInvocation) return;
      if (e instanceof ApiError) {
        error.value = e;
      } else {
        error.value = new ApiError(0, String(e));
      }
    } finally {
      if (invocation === latestInvocation) loading.value = false;
    }
  }

  return { data, error, loading, succeeded, run };
}
