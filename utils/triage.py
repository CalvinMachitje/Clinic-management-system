# utils/triage.py
from your_module import WalkinQueue  # Ensure to replace 'your_module' with the actual module name

def calculate_priority(reason):
    urgent = ['chest pain', 'bleeding', 'unconscious', 'stroke', 'seizure']
    if any(word in reason.lower() for word in urgent):
        return 'high'
    return 'normal'

# In walk-in route:
priority = calculate_priority(request.form['reason'])
queue_entry = WalkinQueue(..., priority=priority)