import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from './client'
import type { components } from './schema'

/** NotificationSettings is the /api/notifications payload. The webhook itself is never returned. */
export type NotificationSettings = components['schemas']['NotificationSettings']

/** SetNotificationSettingsRequest is the PUT body; omitted fields are untouched. */
export type SetNotificationSettingsRequest =
  components['schemas']['SetNotificationSettingsRequest']

export const notificationsKey = ['notifications'] as const

/** notificationsQuery reads the stored notification choices. */
export const notificationsQuery = queryOptions({
  queryKey: notificationsKey,
  queryFn: () => api.get<NotificationSettings>('/api/notifications'),
  staleTime: 30_000,
})

/** useSetNotificationSettings stores the choices and replaces the cached settings. */
export function useSetNotificationSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: SetNotificationSettingsRequest) =>
      api.put<NotificationSettings>('/api/notifications', body),
    onSuccess: (settings) => {
      queryClient.setQueryData(notificationsKey, settings)
    },
  })
}

/** useTestNotification posts a sample message through the stored Slack webhook. */
export function useTestNotification() {
  return useMutation({
    mutationFn: () => api.post<void>('/api/notifications/test'),
  })
}
