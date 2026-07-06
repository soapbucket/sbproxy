import { ref, shallowRef } from "vue";
import { ApiError } from "../api";

export interface AsyncState<T> {
  data: ReturnType<typeof shallowRef<T | null>>;
  error: ReturnType<typeof ref<ApiError | null>>;
  loading: ReturnType<typeof ref<boolean>>;
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

  async function run() {
    loading.value = true;
    error.value = null;
    try {
      data.value = await loader();
    } catch (e) {
      if (e instanceof ApiError) {
        error.value = e;
      } else {
        error.value = new ApiError(0, String(e));
      }
    } finally {
      loading.value = false;
    }
  }

  return { data, error, loading, run };
}
