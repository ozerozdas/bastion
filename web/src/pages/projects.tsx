import { EmptyState } from '../components/empty-state'
import { Button } from '../components/ui/button'

export function ProjectsPage() {
  return (
    <EmptyState
      title="No projects yet"
      body="Projects are the repositories and container images you scan. Add a GitHub connection first, then pick repositories or ECR images from the discover dialog."
    >
      <Button disabled>Add projects</Button>
      <span className="text-xs text-faint">Discovery needs a connection; none exist yet.</span>
    </EmptyState>
  )
}
