import sys

with open('agents/fixer/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = """            with push_lock:
                try:
                    repo.commit_changes(commit_msg, files=summary.files_changed)
                    # Fetch and rebase to merge other threads' pushes
                    repo._repo.git.pull('--rebase', 'origin', branch_name)
                    repo.push_branch(branch_name)
                    return (finding, record, summary)
                except Exception as e:
                    logger.error("Failed to push %s due to rebase conflict or error: %s", finding.component_name, e)
                    try:
                        repo._repo.git.rebase('--abort')
                    except Exception:
                        pass
                    message = f"Merge conflict or push error during combined PR assembly: {e}"
                    current = tracking_store.get(record.tracking_id)
                    if current is not None:
                        current.status = TrackingStatus.ESCALATED.value
                        current.failure_log_excerpt = message[:4000]
                        tracking_store.update(current)
                    return None"""

new_code = """            with push_lock:
                try:
                    repo.commit_changes(commit_msg, files=summary.files_changed)
                    # Fetch and rebase to merge other threads' pushes
                    repo._repo.git.pull('--rebase', 'origin', branch_name)
                    repo.push_branch(branch_name)
                    return (finding, record, summary)
                except Exception as e:
                    logger.warning("Rebase conflict for %s. Retrying fix holding the lock...", finding.component_name)
                    try:
                        repo._repo.git.rebase('--abort')
                    except Exception:
                        pass
                    
                    try:
                        # Reset our branch to match the remote branch (which someone else pushed to)
                        repo._repo.git.fetch('origin', branch_name)
                        repo._repo.git.reset('--hard', f'origin/{branch_name}')
                        
                        # Re-run the fix logic on this new base
                        if finding.is_transitive:
                            summary = fixer.run_transitive_fix(
                                component_name=finding.component_name,
                                current_version=finding.current_version,
                                target_version=finding.recommended_version,
                                introduced_by=finding.introduced_by,
                                tracking_id=record.tracking_id,
                                tracking_store=tracking_store,
                                cve_ids=finding.cve_ids,
                            )
                        else:
                            summary = fixer.run_fresh_fix(
                                component_name=finding.component_name,
                                current_version=finding.current_version,
                                target_version=finding.recommended_version,
                                tracking_id=record.tracking_id,
                                tracking_store=tracking_store,
                                cve_ids=finding.cve_ids,
                                kb_entry=kb_entry,
                            )
                            
                        # Try to commit and push again
                        repo.commit_changes(commit_msg, files=summary.files_changed)
                        repo.push_branch(branch_name)
                        return (finding, record, summary)
                    except Exception as inner_e:
                        logger.error("Failed to re-apply fix during conflict resolution: %s", inner_e)
                        message = f"Merge conflict could not be automatically resolved: {inner_e}"
                        current = tracking_store.get(record.tracking_id)
                        if current is not None:
                            current.status = TrackingStatus.ESCALATED.value
                            current.failure_log_excerpt = message[:4000]
                            tracking_store.update(current)
                        return None"""

content = content.replace(old_code, new_code)

with open('agents/fixer/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
