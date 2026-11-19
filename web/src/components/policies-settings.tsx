import { useQuery } from '@tanstack/react-query'

import { licencePolicyQuery } from '../api/licence-policy'
import { useT } from '../lib/i18n'
import { FindingRulesEditor } from './finding-rules-editor'
import { LicencePolicyEditor } from './licence-policy-card'
import { InfoTip } from './ui/info-tip'

/**
 * PoliciesSettings is Configuration's Policies tab: the licence policy and the
 * noise rules that decide which findings the scans keep showing.
 */
export function PoliciesSettings() {
  const t = useT()
  const { data } = useQuery(licencePolicyQuery())
  const title = t('settings.licence.title')

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <FindingRulesEditor />

      {data ? (
        <section
          aria-label={title}
          className="flex flex-col gap-3 rounded-card border border-border-subtle bg-surface p-4"
        >
          <LicencePolicyEditor
            policy={data}
            heading={
              <>
                <h2 className="text-[0.9375rem] font-semibold">{title}</h2>
                <InfoTip
                  label={t('settings.module.about', { title })}
                  content={t('settings.licence.description')}
                />
              </>
            }
          />
        </section>
      ) : null}
    </div>
  )
}
