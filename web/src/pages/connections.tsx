import { EmptyState } from '../components/empty-state'
import { Button } from '../components/ui/button'

export function ConnectionsPage() {
  return (
    <EmptyState
      title="No connections yet"
      body="Add a GitHub token to list your repositories, an AWS profile for ECR images, or the local Docker socket. Bastion keeps every token in the OS keychain, never in its database."
    >
      <Button disabled>Add connection</Button>
      <span className="text-xs text-faint">Connection setup is not part of this build yet.</span>
    </EmptyState>
  )
}
