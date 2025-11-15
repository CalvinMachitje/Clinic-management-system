# utils/triage.py
def calculate_priority(reason):
    urgent = ['chest pain', 'bleeding', 'unconscious', 'stroke', 'seizure']
    if any(word in reason.lower() for word in urgent):
        return 'high'
    return 'normal'

# In walk-in route:
priority = calculate_priority(request.form['reason'])
queue_entry = WalkinQueue(..., priority=priority)