def combine_scores(trust_score, model_score, trust_weight=0.4, model_weight=0.6):
    # Normalize scores
    trust_normalized = trust_score / 100.0
    model_normalized = model_score / 100.0
    
    # Combine scores
    combined_score = (trust_normalized * trust_weight) + (model_normalized * model_weight)
    
    return combined_score

def is_phishing(trust_score,model_score):
    combined_score_threshold = 0.7
    upper_limit = 90 
    lower_limit = 30
    
    if model_score <= lower_limit:
        return False
    elif model_score >= upper_limit:
        return True
    elif trust_score <= lower_limit:
        return True
    elif trust_score >= upper_limit:
        return False
    else:
        combined_score = combine_scores(trust_score, model_score)
        return combined_score >= combined_score_threshold