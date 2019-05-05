# -*- coding: utf-8 -*-
#Flask modules
from wtforms.validators import DataRequired, Optional, ValidationError, StopValidation

def validate_duration(form, field):
    if int(field.data) <= 0:
        raise ValidationError('Keston on oltava suurempi kuin 0')
