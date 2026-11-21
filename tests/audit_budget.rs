use ladyshell::audit::{
    budget::InvocationBudget,
    model::{Budget, Role},
};
use std::{error::Error, time::Duration};

#[test]
fn hunt_cannot_spend_the_recon_critic_and_verifier_reserve() -> Result<(), Box<dyn Error>> {
    let mut budget = InvocationBudget::new(Budget {
        invocations: 7,
        seconds: 60,
    })?;
    let first = budget.claim(Role::Hunter)?;
    assert_eq!(first, "invocation-1");
    assert!(budget.claim(Role::Hunter).is_err());
    assert_eq!(budget.used(), 1);
    for _ in 0..4 {
        budget.claim(Role::Recon)?;
    }
    budget.claim(Role::Critic)?;
    budget.claim(Role::Verifier)?;
    assert_eq!(budget.used(), 7);
    assert!(budget.claim(Role::Verifier).is_err());
    Ok(())
}

#[test]
fn each_attempt_consumes_budget_even_when_it_never_finishes() -> Result<(), Box<dyn Error>> {
    let mut budget = InvocationBudget::new(Budget {
        invocations: 8,
        seconds: 60,
    })?;
    let first = budget.claim(Role::Recon)?;
    let retry = budget.claim(Role::Recon)?;
    assert_ne!(first, retry);
    assert_eq!(budget.used(), 2);
    budget.claim(Role::Recon)?;
    budget.claim(Role::Recon)?;
    budget.claim(Role::Hunter)?;
    budget.claim(Role::Hunter)?;
    assert!(budget.claim(Role::Hunter).is_err());
    budget.claim(Role::Verifier)?;
    budget.claim(Role::Critic)?;
    assert_eq!(budget.used(), 8);
    Ok(())
}

#[test]
fn reserves_one_verification_for_each_open_candidate() -> Result<(), Box<dyn Error>> {
    let mut budget = InvocationBudget::new(Budget {
        invocations: 9,
        seconds: 60,
    })?;
    for _ in 0..4 {
        budget.claim(Role::Recon)?;
    }
    budget.claim(Role::Hunter)?;
    budget.require_verifications(3)?;
    assert!(budget.claim(Role::Hunter).is_err());
    for _ in 0..3 {
        budget.claim(Role::Verifier)?;
    }
    budget.claim(Role::Critic)?;
    assert_eq!(budget.used(), 9);
    assert!(budget.claim(Role::Verifier).is_err());
    Ok(())
}

#[test]
fn impossible_reserve_blocks_hunting_without_losing_obligations() -> Result<(), Box<dyn Error>> {
    let mut budget = InvocationBudget::new(Budget {
        invocations: 7,
        seconds: 60,
    })?;
    for _ in 0..4 {
        budget.claim(Role::Recon)?;
    }
    budget.claim(Role::Hunter)?;
    budget.require_verifications(2)?;
    assert!(!budget.can_finish());
    assert!(budget.claim(Role::Hunter).is_err());
    // Remaining time is still useful for verification and critique; the run
    // must retain the obligation it cannot satisfy within this budget.
    budget.claim(Role::Verifier)?;
    budget.claim(Role::Critic)?;
    assert!(!budget.can_finish());
    assert!(budget.require_verifications(0).is_err());
    Ok(())
}

#[test]
fn rejects_insufficient_budget_and_stops_at_deadline() -> Result<(), Box<dyn Error>> {
    for invocations in [0, 1, 6] {
        assert!(InvocationBudget::new(Budget {
            invocations,
            seconds: 60
        })
        .is_err());
    }
    assert!(InvocationBudget::new(Budget {
        invocations: 7,
        seconds: 0
    })
    .is_err());
    let mut budget = InvocationBudget::new(Budget {
        invocations: 7,
        seconds: 1,
    })?;
    assert!(budget.time_remaining() <= Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(1010));
    assert!(budget.claim(Role::Recon).is_err());
    assert_eq!(budget.used(), 0);
    assert_eq!(budget.time_remaining(), Duration::ZERO);
    Ok(())
}

#[test]
fn repeated_review_calls_cannot_spend_other_required_roles() -> Result<(), Box<dyn Error>> {
    for role in [Role::Verifier, Role::Critic] {
        let mut budget = InvocationBudget::new(Budget {
            invocations: 7,
            seconds: 60,
        })?;
        budget.claim(role.clone())?;
        assert!(budget.claim(role).is_err());
        assert_eq!(budget.used(), 1);
        assert!(budget.can_finish());
    }
    Ok(())
}

#[test]
fn excessive_candidate_count_does_not_overflow_or_release_reserves() -> Result<(), Box<dyn Error>> {
    let mut budget = InvocationBudget::new(Budget {
        invocations: 7,
        seconds: 60,
    })?;
    budget.require_verifications(u32::MAX)?;
    assert!(!budget.can_finish());
    assert!(budget.claim(Role::Hunter).is_err());
    budget.claim(Role::Verifier)?;
    assert!(budget.claim(Role::Verifier).is_err());
    assert_eq!(budget.used(), 1);
    Ok(())
}
